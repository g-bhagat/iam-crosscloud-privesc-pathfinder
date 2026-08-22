"""
graph_schema.py

Defines the unified identity-graph schema used across AWS, Azure, and GCP
collectors. Every collector normalizes its cloud's native identity model
(IAM roles/policies, Azure AD/RBAC, GCP IAM bindings) into this common
representation so the analysis engine can reason about all three clouds
-- and the edges *between* them -- with one set of algorithms.

Design notes:
- Nodes represent identities, groups, or resources capable of holding
  or granting permissions.
- Edges represent a *capability*, not just a relationship. An edge means
  "source can do X to/with target". This is what makes path-finding work:
  an escalation path is just a walk through capability edges that ends
  at a high-privilege node.
- `risk_weight` on edges lets the pathfinder prefer "easy" escalation
  paths (e.g. a wildcard trust policy) over "hard" ones (e.g. requires
  a specific external ID few would guess).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Cloud(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    CROSS_CLOUD = "cross_cloud"  # for federation / OIDC bridge edges


class NodeType(str, Enum):
    USER = "user"
    ROLE = "role"                 # AWS IAM Role / Azure custom role / GCP predefined+custom role
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"   # GCP SA, Azure Managed Identity, AWS "service role"
    APP_REGISTRATION = "app_registration"  # Azure AD App / Service Principal
    POLICY = "policy"
    RESOURCE = "resource"         # S3 bucket, VM, storage account, GCS bucket, etc.
    ORG_ROOT = "org_root"         # AWS Org, Azure Tenant, GCP Org -- top of blast radius


class EdgeType(str, Enum):
    MEMBER_OF = "member_of"               # user -> group
    CAN_ASSUME = "can_assume"             # identity -> role (sts:AssumeRole / az role assignment)
    CAN_PASS_ROLE = "can_pass_role"       # identity -> role (iam:PassRole and equivalents)
    CAN_IMPERSONATE = "can_impersonate"   # identity -> service_account (GCP actAs / Azure MI)
    CAN_CREATE_RESOURCE = "can_create_resource"  # identity -> resource_type (lambda:CreateFunction, etc.)
    CAN_MODIFY_POLICY = "can_modify_policy"       # identity -> policy (iam:CreatePolicyVersion, etc.)
    CAN_MODIFY_TRUST = "can_modify_trust"         # identity -> role (iam:UpdateAssumeRolePolicy)
    CAN_ATTACH_POLICY = "can_attach_policy"       # identity -> identity (self or other, iam:Attach*Policy)
    HAS_POLICY = "has_policy"             # identity -> policy (attached)
    TRUSTS = "trusts"                     # role -> principal/cloud (trust policy direction)
    FEDERATES_WITH = "federates_with"     # cross-cloud: GCP WIF <-> AWS role, Azure AD OIDC <-> AWS/GCP
    HAS_ACCESS = "has_access"             # identity -> resource (data-plane access, for blast radius)
    ADMIN_OF = "admin_of"                 # identity -> org_root (full control)


@dataclass
class Node:
    id: str                     # globally unique: "aws:role:arn:aws:iam::123:role/X"
    type: NodeType
    cloud: Cloud
    name: str
    is_admin: bool = False       # flagged true if node effectively has admin/owner-equivalent perms
    mfa_enabled: Optional[bool] = None
    external_facing: bool = False  # e.g. federated login, public trust policy, internet-exposed
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        d = self.__dict__.copy()
        d["type"] = self.type.value
        d["cloud"] = self.cloud.value
        return d


@dataclass
class Edge:
    source: str
    target: str
    type: EdgeType
    cloud: Cloud
    risk_weight: float = 1.0     # lower = easier/likelier to exploit; used as traversal cost
    condition: Optional[str] = None  # e.g. IAM condition keys, ABAC constraints that gate the edge
    evidence: Optional[str] = None   # human-readable reason this edge exists (for reports)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        d = self.__dict__.copy()
        d["type"] = self.type.value
        d["cloud"] = self.cloud.value
        return d
