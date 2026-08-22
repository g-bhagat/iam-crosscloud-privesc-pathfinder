"""
gcp_collector.py

GCP IAM + Workload Identity Federation collector. Structure complete;
live calls stubbed (needs a GCP project with Cloud Asset Inventory API
enabled and a read-only service account with roles/cloudasset.viewer +
roles/iam.securityReviewer). Wire up with `google-cloud-asset` +
`google-cloud-iam`.

Same node/edge contract as AWSCollector / AzureCollector.

GCP-specific escalation primitives to surface once wired up:

  - `roles/iam.serviceAccountTokenCreator` on a service account
    -> CAN_IMPERSONATE edge (holder can generate access tokens *as* that
    SA -- this is GCP's direct equivalent of AWS sts:AssumeRole and is
    the single most common GCP privesc primitive).
  - `roles/iam.serviceAccountUser` combined with the ability to attach
    the SA to a new resource (e.g. deploy a Cloud Function / GCE instance
    as that SA) -> CAN_PASS_ROLE equivalent.
  - `roles/resourcemanager.projectIamAdmin` or `roles/owner`
    -> CAN_ATTACH_POLICY (can grant themselves or anyone any role).
  - `roles/iam.workloadIdentityPoolAdmin` or an existing Workload
    Identity Federation pool trusting an external OIDC provider
    (AWS, Azure AD, GitHub Actions) -> FEDERATES_WITH edge. This is
    GCP's most direct cross-cloud bridge and the highest-value thing
    this collector adds to the cross-cloud graph: GCP WIF pools are
    frequently configured to trust an AWS account or GitHub repo far
    more broadly than intended (e.g. missing `attribute.repository`
    condition lets *any* workload in the trusted AWS account/repo
    mint GCP tokens).
  - Service account keys (user-managed) -> external_facing=True on the
    SA node; a leaked key is a standing, non-expiring compromise path
    that doesn't show up in role-assignment analysis alone.
"""

from __future__ import annotations
import logging

from ..graph_schema import Node, Edge, NodeType, EdgeType, Cloud

logger = logging.getLogger(__name__)

HIGH_PRIV_GCP_ROLES = {"roles/owner", "roles/resourcemanager.projectIamAdmin"}


class GCPCollector:
    def __init__(self, asset_client=None, project_id: str | None = None):
        """
        asset_client: an authenticated google.cloud.asset_v1.AssetServiceClient
        project_id: target GCP project (or org for a broader scan)
        """
        self.asset_client = asset_client
        self.project_id = project_id
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def collect(self) -> tuple[list[Node], list[Edge]]:
        if self.asset_client is None:
            logger.warning(
                "GCPCollector running without an asset_client -- "
                "returning empty result. See module docstring to wire up "
                "a live project, or use sample_data/sample_graph.json to demo."
            )
            return [], []

        self._collect_iam_policy_bindings()   # SearchAllIamPolicies -> role bindings per member
        self._collect_service_accounts()      # iam.projects.serviceAccounts.list
        self._collect_sa_iam_bindings()       # per-SA IAM policy -> tokenCreator / SA user edges
        self._collect_workload_identity_pools()  # iam.projects.locations.workloadIdentityPools.list
        return list(self.nodes.values()), self.edges

    def _collect_iam_policy_bindings(self):
        # self.asset_client.search_all_iam_policies(request={"scope": f"projects/{self.project_id}"})
        # -> for each binding: member (user/group/SA) -> role, at a resource scope
        #    if role in HIGH_PRIV_GCP_ROLES: mark is_admin / CAN_ATTACH_POLICY
        raise NotImplementedError("Wire up Cloud Asset Inventory SearchAllIamPolicies")

    def _collect_service_accounts(self):
        # iam_client.projects().serviceAccounts().list(name=f"projects/{self.project_id}")
        # -> NodeType.SERVICE_ACCOUNT nodes; check for user-managed keys -> external_facing=True
        raise NotImplementedError("Wire up IAM serviceAccounts.list")

    def _collect_sa_iam_bindings(self):
        # For each SA: iam_client.projects().serviceAccounts().getIamPolicy(...)
        # -> members with roles/iam.serviceAccountTokenCreator get CAN_IMPERSONATE
        #    members with roles/iam.serviceAccountUser get CAN_PASS_ROLE (paired
        #    with resource-creation permission elsewhere in the project)
        raise NotImplementedError("Wire up per-SA getIamPolicy calls")

    def _collect_workload_identity_pools(self):
        # iam_client.projects().locations().workloadIdentityPools().list(...)
        # then .providers().list(...) per pool to read the OIDC issuer +
        # attribute-condition mapping.
        # -> FEDERATES_WITH edge from the external identity (AWS role ARN
        #    pattern, GitHub repo, Azure AD tenant) to the impersonated GCP SA.
        #    THIS IS THE KEY CROSS-CLOUD EDGE. Flag pools with no
        #    attribute-condition as external_facing / high risk_weight.
        raise NotImplementedError("Wire up Workload Identity Pool + Provider listing")
