"""
gcp_collector.py

Live GCP IAM + Workload Identity Federation collector. Read-only: only
calls List/Get/Search/getIamPolicy APIs -- see terraform/scanner/ (AWS
half exists today; the GCP half of task 5 still needs writing) for the
intended least-privilege role set: `roles/cloudasset.viewer` for
SearchAllIamPolicies, plus the IAM Admin API's `iam.serviceAccounts.list`,
`iam.serviceAccounts.get`, `iam.serviceAccounts.getIamPolicy`,
`iam.workloadIdentityPools.list`, `iam.workloadIdentityPoolProviders.list`
read permissions (`roles/iam.securityReviewer` covers all of these).

Same node/edge contract as AWSCollector / AzureCollector. Uses two
separate GCP client objects, both constructed by the caller and passed
in (mirrors AWSCollector taking an already-authenticated boto3_session --
this collector doesn't build its own credentials):

  asset_client: an authenticated google.cloud.asset_v1.AssetServiceClient
      -- used only for _collect_iam_policy_bindings (SearchAllIamPolicies).
  iam_client: an authenticated IAM Admin API v1 client built via
      googleapiclient.discovery.build("iam", "v1", credentials=...) --
      used for everything else. The Workload Identity Pool/Provider
      admin surface and per-SA IAM policy calls aren't covered by the
      newer google-cloud-iam gRPC client at the time this was written,
      so this intentionally uses the REST discovery client instead, not
      `google.cloud.iam_admin_v1`.

What it builds:
- SERVICE_ACCOUNT nodes for every SA in the project (_collect_service_accounts)
  -- external_facing=True if it has any USER_MANAGED key (a leaked key is a
  standing, non-expiring compromise path that doesn't show up in
  role-assignment analysis alone).
- CAN_IMPERSONATE edges from `roles/iam.serviceAccountTokenCreator`
  bindings on a SA (GCP's direct equivalent of AWS sts:AssumeRole, and
  the single most common GCP privesc primitive) (_collect_sa_iam_bindings).
- CAN_PASS_ROLE edges from `roles/iam.serviceAccountUser` bindings on a SA
  (_collect_sa_iam_bindings).
- FEDERATES_WITH edges from `roles/iam.workloadIdentityUser` bindings on a
  SA, resolved against whichever WIF provider(s) in the referenced pool
  actually map the attribute the binding's member string names
  (_collect_sa_iam_bindings + _collect_workload_identity_pools together --
  see _emit_workload_identity_edge). THIS IS THE KEY CROSS-CLOUD EDGE and
  the exact mechanism Track 1's planted misconfiguration uses. When the
  matched provider trusts an AWS account directly (Track 2's mechanism,
  no third-party OIDC issuer) rather than a bridged third-party issuer,
  the edge's source is a synthetic `aws:external_account:<id>` node
  standing in for "any principal in that AWS account" -- there's no
  bridge node to originate from, and correlation.py's
  merge_direct_references() only ever rewrites an edge that already
  exists, never creates one, so this collector has to emit the edge
  itself rather than leave it for correlation to conjure up.
- APP_REGISTRATION/CROSS_CLOUD bridge nodes, one per distinct OIDC issuer
  URI seen across every WIF provider in the project -- regardless of
  whether any SA binding currently references that provider yet, mirroring
  AWSCollector's _collect_oidc_providers design (task 8's counterpart to
  the AWS-side fix made for task 5/7).
- is_admin=True + a CAN_ATTACH_POLICY self-loop on any member (user,
  group, domain, or SA) holding `roles/owner` or
  `roles/resourcemanager.projectIamAdmin` anywhere Cloud Asset Inventory's
  SearchAllIamPolicies surfaces it (_collect_iam_policy_bindings).

Like AWSCollector, this does NOT attempt to fully evaluate IAM policy or
WIF attribute-mapping semantics -- it uses the same pragmatic,
name/shape-based heuristic (see aws_collector.py's docstring for the
rationale), and the same error-handling style: a failed lookup on one
resource logs a warning and moves on, it never aborts the whole collect().
"""

from __future__ import annotations

import logging
import re

from ..graph_schema import Cloud, Edge, EdgeType, Node, NodeType

logger = logging.getLogger(__name__)

HIGH_PRIV_GCP_ROLES = {"roles/owner", "roles/resourcemanager.projectIamAdmin"}

# principalSet://iam.googleapis.com/projects/{P}/locations/{L}/workloadIdentityPools/{POOL}/attribute.{X}/{V}
# principal://iam.googleapis.com/projects/{P}/locations/{L}/workloadIdentityPools/{POOL}/subject/{V}
# The (pool resource name, attribute segment) split is what
# _emit_workload_identity_edge matches against each pool's providers'
# attribute_mapping. See https://cloud.google.com/iam/docs/workload-identity-federation
_WIF_MEMBER_RE = re.compile(
    r"^principal(?:Set)?://iam\.googleapis\.com/"
    r"(projects/[^/]+/locations/[^/]+/workloadIdentityPools/[^/]+)/(.+)$"
)


class GCPCollector:
    def __init__(self, asset_client=None, iam_client=None, project_id: str | None = None):
        """
        asset_client: an authenticated google.cloud.asset_v1.AssetServiceClient
        iam_client: an authenticated IAM Admin API v1 client, e.g.
            googleapiclient.discovery.build("iam", "v1", credentials=creds)
        project_id: target GCP project (or org for a broader scan)
        """
        self.asset_client = asset_client
        self.iam_client = iam_client
        self.project_id = project_id
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        # pool resource name -> list of {bridge_id, aws_account_id,
        # attribute_condition, attribute_mapping, name} dicts, populated by
        # _collect_workload_identity_pools and consumed by
        # _collect_sa_iam_bindings' _emit_workload_identity_edge. Internal
        # bookkeeping, not part of the public node/edge output.
        self._providers_by_pool: dict[str, list[dict]] = {}

    # ---------- public entrypoint ----------

    def collect(self) -> tuple[list[Node], list[Edge]]:
        if self.asset_client is None or self.iam_client is None:
            logger.warning(
                "GCPCollector running without an asset_client/iam_client -- "
                "returning empty result. See module docstring to wire up "
                "a live project, or use sample_data/sample_graph.json to demo."
            )
            return [], []

        logger.info("Collecting GCP IAM identities for project %s", self.project_id)
        # Pools/providers first: populates self._providers_by_pool and the
        # OIDC bridge nodes, which _collect_sa_iam_bindings needs in order
        # to resolve a workloadIdentityUser binding's member string into
        # the right FEDERATES_WITH edge(s).
        self._collect_workload_identity_pools()
        self._collect_service_accounts()
        self._collect_sa_iam_bindings()
        self._collect_iam_policy_bindings()
        return list(self.nodes.values()), self.edges

    # ---------- collection stages ----------

    def _collect_workload_identity_pools(self):
        parent = f"projects/{self.project_id}/locations/global"
        try:
            pools_resp = (
                self.iam_client.projects().locations().workloadIdentityPools().list(parent=parent).execute()
            )
        except Exception as e:
            logger.warning("Could not list workload identity pools for %s: %s", parent, e)
            return

        for pool in pools_resp.get("workloadIdentityPools", []):
            pool_name = pool["name"]  # projects/{proj}/locations/global/workloadIdentityPools/{id}
            try:
                providers_resp = (
                    self.iam_client.projects()
                    .locations()
                    .workloadIdentityPools()
                    .providers()
                    .list(parent=pool_name)
                    .execute()
                )
            except Exception as e:
                logger.warning("Could not list providers for pool %s: %s", pool_name, e)
                continue

            for provider in providers_resp.get("workloadIdentityPoolProviders", []):
                if provider.get("disabled"):
                    continue
                self._register_provider(pool_name, provider)

    def _register_provider(self, pool_name: str, provider: dict):
        # Raw CEL string, passed through untouched -- confidence.py's
        # score_gcp_condition() is what interprets this, not this collector.
        attribute_condition = provider.get("attributeCondition")
        attribute_mapping = provider.get("attributeMapping", {})
        provider_name = provider.get("name", pool_name)

        oidc = provider.get("oidc")
        aws = provider.get("aws")

        entry = {
            "name": provider_name,
            "attribute_condition": attribute_condition,
            "attribute_mapping": attribute_mapping,
        }

        if oidc and oidc.get("issuerUri"):
            # Pattern 1 shape: third-party OIDC issuer (e.g. GitHub Actions).
            # setdefault, not assignment: a pool commonly holds MULTIPLE
            # providers sharing one issuer_uri (Track 1's loose + scoped
            # providers both point at GitHub Actions) -- they fan out as
            # separate edges from the SAME bridge node, not each overwrite
            # it. Node created regardless of whether any SA binding
            # references this provider yet, mirroring _collect_oidc_providers
            # on the AWS side (task 7).
            bridge_id = f"gcp:wif_bridge:{oidc['issuerUri']}"
            self.nodes.setdefault(
                bridge_id,
                Node(
                    id=bridge_id,
                    type=NodeType.APP_REGISTRATION,
                    cloud=Cloud.CROSS_CLOUD,
                    name=oidc["issuerUri"],
                    external_facing=True,
                ),
            )
            entry["bridge_id"] = bridge_id
        elif aws and aws.get("accountId"):
            # Pattern 2/3 shape: GCP trusting an AWS account directly, no
            # third-party issuer -- no bridge node here. correlation.py's
            # merge_direct_references() resolves this via whatever AWS role
            # ARN, if any, attribute_condition names.
            entry["bridge_id"] = None
            entry["aws_account_id"] = aws["accountId"]
        else:
            logger.warning("Provider %s has neither oidc.issuerUri nor aws.accountId -- skipping", provider_name)
            return

        self._providers_by_pool.setdefault(pool_name, []).append(entry)

    def _collect_service_accounts(self):
        request = self.iam_client.projects().serviceAccounts().list(name=f"projects/{self.project_id}")
        while request is not None:
            try:
                response = request.execute()
            except Exception as e:
                logger.warning("Could not list service accounts for project %s: %s", self.project_id, e)
                return
            for sa in response.get("accounts", []):
                self._add_service_account(sa)
            request = self.iam_client.projects().serviceAccounts().list_next(request, response)

    def _add_service_account(self, sa: dict):
        node_id = self._sa_node_id(sa["email"])
        self.nodes[node_id] = Node(
            id=node_id,
            type=NodeType.SERVICE_ACCOUNT,
            cloud=Cloud.GCP,
            name=sa["email"],
            attributes={
                "resource_name": sa["name"],
                "unique_id": sa.get("uniqueId", ""),
                "display_name": sa.get("displayName", ""),
                "disabled": sa.get("disabled", False),
            },
        )
        self._flag_user_managed_keys(node_id, sa["name"])

    def _flag_user_managed_keys(self, node_id: str, sa_resource_name: str):
        try:
            resp = (
                self.iam_client.projects()
                .serviceAccounts()
                .keys()
                .list(name=sa_resource_name, keyTypes=["USER_MANAGED"])
                .execute()
            )
        except Exception as e:
            logger.warning("Could not list keys for %s: %s", sa_resource_name, e)
            return
        keys = resp.get("keys", [])
        if keys:
            self.nodes[node_id].external_facing = True
            self.nodes[node_id].attributes["user_managed_key_count"] = len(keys)

    def _collect_sa_iam_bindings(self):
        # Iterate the SA nodes _collect_service_accounts already built,
        # rather than listing again -- resource_name is already on hand.
        for node in [n for n in self.nodes.values() if n.type == NodeType.SERVICE_ACCOUNT]:
            resource_name = node.attributes.get("resource_name")
            if not resource_name:
                continue
            try:
                policy = self.iam_client.projects().serviceAccounts().getIamPolicy(resource=resource_name).execute()
            except Exception as e:
                logger.warning("Could not get IAM policy for %s: %s", node.name, e)
                continue

            for binding in policy.get("bindings", []):
                role = binding.get("role")
                for member in binding.get("members", []):
                    if role == "roles/iam.workloadIdentityUser":
                        self._emit_workload_identity_edge(member, node)
                    elif role == "roles/iam.serviceAccountTokenCreator":
                        self._emit_impersonation_edge(member, node, EdgeType.CAN_IMPERSONATE, role)
                    elif role == "roles/iam.serviceAccountUser":
                        self._emit_impersonation_edge(member, node, EdgeType.CAN_PASS_ROLE, role)

    def _emit_workload_identity_edge(self, member: str, sa_node: Node):
        m = _WIF_MEMBER_RE.match(member)
        if not m:
            logger.warning("Unrecognized workloadIdentityUser member format on %s: %s", sa_node.name, member)
            return
        pool_name, attribute_path = m.group(1), m.group(2)
        # ".../attribute.repository_owner/acme-corp" -> "attribute.repository_owner"
        # ".../subject/some-subject-value" -> "subject" -> maps to "google.subject"
        attribute_key = attribute_path.split("/", 1)[0]
        mapping_key = "google.subject" if attribute_key == "subject" else attribute_key

        providers = self._providers_by_pool.get(pool_name, [])
        matched = False
        for provider in providers:
            if mapping_key not in (provider.get("attribute_mapping") or {}):
                continue
            matched = True
            bridge_id = provider.get("bridge_id")
            if bridge_id is None:
                # AWS-principal provider (Track 2's actual mechanism: a GCP
                # WIF pool trusting an AWS account directly, no third-party
                # OIDC issuer involved) -- no bridge node, so emit a direct
                # edge instead, from a synthetic node standing in for "any
                # principal in this trusted AWS account" straight to the SA
                # (already precisely known -- this IS the specific SA whose
                # IAM policy grants the binding). Previously this branch
                # emitted nothing at all, on the theory that
                # correlation.py's merge_direct_references() would resolve
                # it -- but that function only ever REWRITES an edge that
                # already exists; it never creates one from scratch. With
                # nothing emitted here, real Track 2 infrastructure (a live,
                # working AWS->GCP token exchange) produced zero edges,
                # zero findings, zero paths. attribute_condition (the CEL
                # scoping condition) travels on the edge unchanged, same as
                # the bridge-node branch below -- confidence.py's
                # score_gcp_condition() is what actually distinguishes
                # Track 2's loosely-scoped (MEDIUM) misconfiguration from a
                # correctly role-scoped (HIGH) control, off this same
                # condition string.
                account_id = provider.get("aws_account_id")
                source_id = self._aws_external_account_node_id(account_id)
                self.nodes.setdefault(
                    source_id,
                    Node(
                        id=source_id,
                        # No specific IAM role/user is named -- mirrors
                        # _member_to_node's allUsers/allAuthenticatedUsers
                        # handling on the GCP side: NodeType.USER stands in
                        # for "an unresolved, broad set of principals",
                        # not one first-class identity.
                        type=NodeType.USER,
                        cloud=Cloud.AWS,
                        name=f"any AWS principal in account {account_id}",
                        external_facing=True,
                        attributes={"aws_account_id": account_id},
                    ),
                )
                self.edges.append(
                    Edge(
                        source=source_id,
                        target=sa_node.id,
                        type=EdgeType.FEDERATES_WITH,
                        cloud=Cloud.CROSS_CLOUD,
                        condition=provider.get("attribute_condition"),
                        evidence=(
                            f"Workload Identity Federation binding ({provider['name']}) trusts AWS "
                            f"account {account_id} directly -- no third-party OIDC issuer involved"
                        ),
                        attributes={"aws_account_id": account_id},
                    )
                )
                continue
            self.edges.append(
                Edge(
                    source=bridge_id,
                    target=sa_node.id,
                    type=EdgeType.FEDERATES_WITH,
                    cloud=Cloud.CROSS_CLOUD,
                    condition=provider.get("attribute_condition"),
                    evidence=f"Workload Identity Federation binding ({provider['name']})",
                )
            )
        if not matched:
            logger.warning(
                "workloadIdentityUser member on %s references pool %s but no provider maps %s -- "
                "binding may reference a provider this collector couldn't read",
                sa_node.name,
                pool_name,
                mapping_key,
            )

    def _emit_impersonation_edge(self, member: str, sa_node: Node, edge_type: EdgeType, role: str):
        if member.startswith(("principalSet://", "principal://")):
            # A WIF-federated identity impersonating via serviceAccountUser/
            # tokenCreator directly (rather than workloadIdentityUser) is a
            # narrower, less common shape -- not resolved to a cross-cloud
            # bridge here to keep this collector's scope matched to Track 1's
            # actual mechanism (roles/iam.workloadIdentityUser). Logged, not
            # silently dropped.
            logger.info("Skipping non-workloadIdentityUser WIF member on %s (%s): %s", sa_node.name, role, member)
            return
        source_node = self._member_to_node(member)
        if source_node is None:
            return
        self.edges.append(
            Edge(
                source=source_node.id,
                target=sa_node.id,
                type=edge_type,
                cloud=Cloud.GCP,
                risk_weight=0.5,
                evidence=f"Holds '{role}' on {sa_node.name}",
            )
        )

    def _collect_iam_policy_bindings(self):
        scope = f"projects/{self.project_id}"
        try:
            results = self.asset_client.search_all_iam_policies(request={"scope": scope})
        except Exception as e:
            logger.warning("Could not search IAM policies via Cloud Asset Inventory for %s: %s", scope, e)
            return

        try:
            for result in results:
                self._process_iam_policy_search_result(result)
        except Exception as e:
            # Errors mid-pagination land here (a single malformed page
            # shouldn't lose everything already collected).
            logger.warning("Error while paging through IAM policy search results: %s", e)

    def _process_iam_policy_search_result(self, result):
        policy = result.policy
        if not policy or not policy.bindings:
            return
        for binding in policy.bindings:
            role = binding.role
            if role not in HIGH_PRIV_GCP_ROLES:
                continue
            for member in binding.members:
                node = self._member_to_node(member)
                if node is None:
                    continue
                node.is_admin = True
                self.edges.append(
                    Edge(
                        source=node.id,
                        target=node.id,
                        type=EdgeType.CAN_ATTACH_POLICY,
                        cloud=Cloud.GCP,
                        risk_weight=0.5,
                        evidence=f"Holds '{role}' on {result.resource}",
                    )
                )
                # NOTE: source==target self-loop, same placeholder pattern
                # AWSCollector._emit_sensitive_edges uses -- marks "this
                # identity holds this capability"; escalation_rules.py
                # resolves is_admin reachability directly via the node flag.

    # ---------- helpers ----------

    def _sa_node_id(self, email: str) -> str:
        return f"gcp:service_account:{email}"

    def _aws_external_account_node_id(self, account_id: str) -> str:
        return f"aws:external_account:{account_id}"

    def _member_to_node(self, member: str) -> Node | None:
        """
        Parse a GCP IAM policy member string into a graph Node, creating it
        if it doesn't exist yet. Returns None for member shapes this
        collector doesn't model as a first-class node (principalSet://
        and principal:// are handled by the WIF-specific paths above, not
        here -- if one reaches this method it means a HIGH_PRIV_GCP_ROLES
        binding was granted directly to a WIF identity at the project
        level, skipping the SA-impersonation step Track 1 uses; still
        surfaced as a generic external node so it isn't silently lost).
        """
        if member in ("allUsers", "allAuthenticatedUsers"):
            node_id = f"gcp:external:{member}"
            return self.nodes.setdefault(
                node_id,
                Node(id=node_id, type=NodeType.USER, cloud=Cloud.GCP, name=member, external_facing=True),
            )
        if member.startswith("serviceAccount:"):
            email = member.split(":", 1)[1]
            node_id = self._sa_node_id(email)
            return self.nodes.setdefault(
                node_id, Node(id=node_id, type=NodeType.SERVICE_ACCOUNT, cloud=Cloud.GCP, name=email)
            )
        if member.startswith("user:"):
            email = member.split(":", 1)[1]
            node_id = f"gcp:user:{email}"
            return self.nodes.setdefault(node_id, Node(id=node_id, type=NodeType.USER, cloud=Cloud.GCP, name=email))
        if member.startswith("group:"):
            email = member.split(":", 1)[1]
            node_id = f"gcp:group:{email}"
            return self.nodes.setdefault(node_id, Node(id=node_id, type=NodeType.GROUP, cloud=Cloud.GCP, name=email))
        if member.startswith("domain:"):
            domain = member.split(":", 1)[1]
            node_id = f"gcp:domain:{domain}"
            return self.nodes.setdefault(
                node_id,
                Node(id=node_id, type=NodeType.GROUP, cloud=Cloud.GCP, name=domain, external_facing=True),
            )
        if member.startswith(("principalSet://", "principal://")):
            node_id = f"gcp:wif_principal:{member}"
            return self.nodes.setdefault(
                node_id,
                Node(
                    id=node_id,
                    type=NodeType.APP_REGISTRATION,
                    cloud=Cloud.CROSS_CLOUD,
                    name=member,
                    external_facing=True,
                    attributes={"note": "direct grant to a WIF-federated identity, not resolved to an OIDC bridge"},
                ),
            )
        logger.warning("Unrecognized IAM member format: %s", member)
        return None
