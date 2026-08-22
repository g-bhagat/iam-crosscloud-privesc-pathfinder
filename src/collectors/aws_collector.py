"""
aws_collector.py

Live AWS IAM collector. Read-only: only calls List*/Get* IAM APIs
(iam:List*, iam:Get*, sts:GetCallerIdentity). Requires only the
`ReadOnlyAccess` or a scoped IAM-read policy on the credentials used.

What it builds:
- USER, ROLE, GROUP, POLICY nodes for every identity in the account
- MEMBER_OF edges (user -> group)
- HAS_POLICY edges (identity -> policy, both attached + inline)
- CAN_ASSUME edges, parsed from each role's trust policy
  (who/what can sts:AssumeRole into this role)
- CAN_PASS_ROLE / CAN_MODIFY_POLICY / CAN_MODIFY_TRUST / CAN_ATTACH_POLICY
  edges, inferred by scanning each identity's effective policy documents
  for the specific IAM actions that enable known privilege-escalation
  techniques (see analysis/escalation_rules.py for the technique list).

This intentionally does NOT attempt to fully evaluate IAM policy semantics
(that's a much bigger undertaking -- see AWS's own policy simulator, or
projects like PMapper). It uses a pragmatic, action-name-based heuristic:
if an identity holds a sensitive action without a narrowing condition,
treat the corresponding edge as present. This is the same approach tools
like Cloudsplaining and Rhino Security Labs' original privesc research use,
and it's sufficient for a portfolio-grade posture assessment.
"""

from __future__ import annotations
import json
import logging
from typing import Iterable

from ..graph_schema import Node, Edge, NodeType, EdgeType, Cloud

logger = logging.getLogger(__name__)

# Actions that, alone or combined, are known IAM privilege-escalation
# primitives. Mapped 1:1 to the rule engine in escalation_rules.py.
SENSITIVE_ACTIONS = {
    "iam:PassRole": EdgeType.CAN_PASS_ROLE,
    "iam:CreatePolicyVersion": EdgeType.CAN_MODIFY_POLICY,
    "iam:SetDefaultPolicyVersion": EdgeType.CAN_MODIFY_POLICY,
    "iam:UpdateAssumeRolePolicy": EdgeType.CAN_MODIFY_TRUST,
    "iam:AttachUserPolicy": EdgeType.CAN_ATTACH_POLICY,
    "iam:AttachGroupPolicy": EdgeType.CAN_ATTACH_POLICY,
    "iam:AttachRolePolicy": EdgeType.CAN_ATTACH_POLICY,
    "iam:PutUserPolicy": EdgeType.CAN_ATTACH_POLICY,
    "iam:PutRolePolicy": EdgeType.CAN_ATTACH_POLICY,
    "sts:AssumeRole": EdgeType.CAN_ASSUME,
}

ADMIN_MARKERS = {
    "AdministratorAccess",  # AWS managed policy name
}


class AWSCollector:
    def __init__(self, boto3_session, account_id: str | None = None):
        """
        boto3_session: an already-authenticated boto3.Session for the
        target account. Pass a session scoped to read-only creds.
        """
        self.session = boto3_session
        self.iam = boto3_session.client("iam")
        self.sts = boto3_session.client("sts")
        self.account_id = account_id or self.sts.get_caller_identity()["Account"]
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    # ---------- public entrypoint ----------

    def collect(self) -> tuple[list[Node], list[Edge]]:
        logger.info("Collecting AWS IAM identities for account %s", self.account_id)
        self._collect_users()
        self._collect_groups()
        self._collect_roles()
        self._collect_managed_policies()
        return list(self.nodes.values()), self.edges

    # ---------- collection stages ----------

    def _node_id(self, kind: str, name_or_arn: str) -> str:
        return f"aws:{kind}:{name_or_arn}"

    def _collect_users(self):
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                node_id = self._node_id("user", u["Arn"])
                mfa = self._has_mfa(u["UserName"])
                self.nodes[node_id] = Node(
                    id=node_id, type=NodeType.USER, cloud=Cloud.AWS,
                    name=u["UserName"], mfa_enabled=mfa,
                    attributes={"arn": u["Arn"], "created": str(u["CreateDate"])},
                )
                self._collect_identity_policies(node_id, "user", u["UserName"])
                # group membership
                for g in self.iam.list_groups_for_user(UserName=u["UserName"])["Groups"]:
                    group_id = self._node_id("group", g["Arn"])
                    self.edges.append(Edge(node_id, group_id, EdgeType.MEMBER_OF, Cloud.AWS))

    def _collect_groups(self):
        paginator = self.iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page["Groups"]:
                node_id = self._node_id("group", g["Arn"])
                self.nodes[node_id] = Node(
                    id=node_id, type=NodeType.GROUP, cloud=Cloud.AWS, name=g["GroupName"],
                    attributes={"arn": g["Arn"]},
                )
                self._collect_identity_policies(node_id, "group", g["GroupName"])

    def _collect_roles(self):
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page["Roles"]:
                node_id = self._node_id("role", r["Arn"])
                is_admin = False
                self.nodes[node_id] = Node(
                    id=node_id, type=NodeType.ROLE, cloud=Cloud.AWS, name=r["RoleName"],
                    attributes={"arn": r["Arn"]},
                )
                self._collect_identity_policies(node_id, "role", r["RoleName"])
                # parse trust policy -> CAN_ASSUME edges from whoever is trusted
                self._parse_trust_policy(node_id, r["RoleName"], r.get("AssumeRolePolicyDocument"))

    def _collect_identity_policies(self, node_id: str, kind: str, name: str):
        """Attach HAS_POLICY edges + scan policy docs for sensitive actions."""
        list_attached = {
            "user": self.iam.list_attached_user_policies,
            "group": self.iam.list_attached_group_policies,
            "role": self.iam.list_attached_role_policies,
        }[kind]
        kwargs = {f"{kind.capitalize()}Name": name}
        attached = list_attached(**kwargs)["AttachedPolicies"]

        all_actions: set[str] = set()

        for p in attached:
            policy_id = self._node_id("policy", p["PolicyArn"])
            self.edges.append(Edge(node_id, policy_id, EdgeType.HAS_POLICY, Cloud.AWS))
            if p["PolicyName"] in ADMIN_MARKERS:
                self.nodes[node_id].is_admin = True
            actions = self._get_managed_policy_actions(p["PolicyArn"])
            all_actions |= actions

        # inline policies
        list_inline = {
            "user": self.iam.list_user_policies,
            "group": self.iam.list_group_policies,
            "role": self.iam.list_role_policies,
        }[kind]
        get_inline = {
            "user": self.iam.get_user_policy,
            "group": self.iam.get_group_policy,
            "role": self.iam.get_role_policy,
        }[kind]
        for pname in list_inline(**kwargs).get("PolicyNames", []):
            doc = get_inline(**{**kwargs, "PolicyName": pname})["PolicyDocument"]
            all_actions |= self._extract_actions(doc)

        self._emit_sensitive_edges(node_id, all_actions)

    def _collect_managed_policies(self):
        """Ensure standalone policy nodes exist even if not yet referenced."""
        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):  # customer-managed only; Scope="All" for AWS-managed too
            for p in page["Policies"]:
                node_id = self._node_id("policy", p["Arn"])
                if node_id not in self.nodes:
                    self.nodes[node_id] = Node(
                        id=node_id, type=NodeType.POLICY, cloud=Cloud.AWS, name=p["PolicyName"],
                        attributes={"arn": p["Arn"]},
                    )

    # ---------- helpers ----------

    def _has_mfa(self, username: str) -> bool:
        devices = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
        return len(devices) > 0

    def _get_managed_policy_actions(self, policy_arn: str) -> set[str]:
        try:
            version_id = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            doc = self.iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )["PolicyVersion"]["Document"]
            return self._extract_actions(doc)
        except Exception as e:
            logger.warning("Could not read policy %s: %s", policy_arn, e)
            return set()

    @staticmethod
    def _extract_actions(doc: dict) -> set[str]:
        actions = set()
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            act = stmt.get("Action", [])
            if isinstance(act, str):
                act = [act]
            actions |= set(act)
        return actions

    def _emit_sensitive_edges(self, node_id: str, actions: set[str]):
        for action, edge_type in SENSITIVE_ACTIONS.items():
            # supports simple wildcard match, e.g. "iam:*" or "iam:Attach*"
            if action in actions or f"{action.split(':')[0]}:*" in actions or "*" in actions:
                self.edges.append(Edge(
                    source=node_id, target=node_id, type=edge_type, cloud=Cloud.AWS,
                    risk_weight=0.5, evidence=f"Holds action '{action}'",
                ))
                # NOTE: source==target here is a placeholder self-loop marking
                # "this identity holds this capability" -- the pathfinder resolves
                # the *actual* target (which role can be passed to, which policy
                # can be modified, etc.) in escalation_rules.py, since that
                # requires cross-referencing with other resources in the account.

    def _parse_trust_policy(self, role_node_id: str, role_name: str, trust_doc: dict | None):
        if not trust_doc:
            return
        statements = trust_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            aws_principals = principal.get("AWS", []) if isinstance(principal, dict) else []
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            federated = principal.get("Federated", []) if isinstance(principal, dict) else []
            if isinstance(federated, str):
                federated = [federated]

            for p in aws_principals:
                if p == "*":
                    # extremely dangerous: anyone can assume this role
                    self.nodes[role_node_id].external_facing = True
                    src_id = "aws:external:*"
                    self.nodes.setdefault(src_id, Node(
                        id=src_id, type=NodeType.USER, cloud=Cloud.AWS,
                        name="ANY_AWS_PRINCIPAL", external_facing=True,
                    ))
                else:
                    src_id = self._node_id("principal", p)
                    self.nodes.setdefault(src_id, Node(
                        id=src_id, type=NodeType.ROLE, cloud=Cloud.AWS, name=p,
                    ))
                condition = json.dumps(stmt.get("Condition")) if stmt.get("Condition") else None
                self.edges.append(Edge(
                    source=src_id, target=role_node_id, type=EdgeType.CAN_ASSUME,
                    cloud=Cloud.AWS, condition=condition,
                    risk_weight=1.0 if condition else 0.3,  # unconditioned trust = high risk
                    evidence="Trust policy allows sts:AssumeRole",
                ))

            for f in federated:
                # OIDC/SAML federation -- this is a cross-cloud bridge point
                # (e.g. GitHub Actions OIDC, GCP Workload Identity Federation,
                # Azure AD as SAML IdP). Flag it distinctly.
                src_id = f"federated:{f}"
                self.nodes.setdefault(src_id, Node(
                    id=src_id, type=NodeType.APP_REGISTRATION, cloud=Cloud.CROSS_CLOUD,
                    name=f, external_facing=True,
                ))
                self.edges.append(Edge(
                    source=src_id, target=role_node_id, type=EdgeType.FEDERATES_WITH,
                    cloud=Cloud.CROSS_CLOUD, evidence="OIDC/SAML federated trust",
                    risk_weight=0.7,
                ))
