"""
azure_collector.py

Azure AD (Entra ID) + RBAC collector. STRUCTURE IS COMPLETE; the live
Microsoft Graph / ARM calls are stubbed with clear TODOs because they
require an Azure tenant with Graph API permissions
(Directory.Read.All, RoleManagement.Read.Directory, Application.Read.All)
that aren't available in this environment. Wire it up against your own
free-tier Azure AD tenant (app registrations are free; use `azure-identity`
+ `msgraph-sdk` with a read-only app registration).

Mirrors the same node/edge output contract as aws_collector.AWSCollector
so the graph builder can merge both without special-casing.

Key Azure-specific escalation primitives this collector should surface
once wired up (these are the Azure equivalents of the AWS IAM techniques):

  - Owner / User Access Administrator RBAC role on a subscription or
    resource group  -> effectively CAN_ATTACH_POLICY (can grant themselves
    or anyone else any role, including Owner).
  - Service Principal with "Application Administrator" or
    "Privileged Role Administrator" AAD role -> CAN_ATTACH_POLICY
    (can add credentials to / assume the identity of other app registrations,
    including ones with high-privilege API permissions).
  - App registration granted an *application permission* (not delegated)
    such as RoleManagement.ReadWrite.Directory -> CAN_MODIFY_TRUST equivalent
    (can grant itself Global Administrator via directory role assignment).
  - Managed Identity federated to a GitHub Actions / AWS OIDC provider
    -> FEDERATES_WITH edge (cross-cloud bridge).
  - "Contributor" role (not just Owner) combined with a User Assigned
    Managed Identity that has a higher-privileged role elsewhere
    -> CAN_IMPERSONATE chain (Contributor can attach the MI to a new
    resource and use its token).
"""

from __future__ import annotations
import logging

from ..graph_schema import Node, Edge, NodeType, EdgeType, Cloud

logger = logging.getLogger(__name__)

HIGH_PRIV_AAD_ROLES = {"Global Administrator", "Privileged Role Administrator"}
HIGH_PRIV_RBAC_ROLES = {"Owner", "User Access Administrator"}


class AzureCollector:
    def __init__(self, graph_client=None, subscription_id: str | None = None):
        """
        graph_client: an authenticated msgraph.GraphServiceClient
                      (azure-identity DefaultAzureCredential recommended,
                      scoped to a read-only app registration).
        subscription_id: target subscription for RBAC role assignment pull.
        """
        self.graph_client = graph_client
        self.subscription_id = subscription_id
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def collect(self) -> tuple[list[Node], list[Edge]]:
        if self.graph_client is None:
            logger.warning(
                "AzureCollector running without a graph_client -- "
                "returning empty result. See module docstring to wire up "
                "a live tenant, or use sample_data/sample_graph.json to demo."
            )
            return [], []

        self._collect_users_and_groups()      # GET /users, /groups, /groups/{id}/members
        self._collect_service_principals()     # GET /servicePrincipals
        self._collect_app_registrations()      # GET /applications (+ requiredResourceAccess -> API perms)
        self._collect_directory_role_assignments()  # GET /roleManagement/directory/roleAssignments
        self._collect_rbac_role_assignments()  # ARM: GET /subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments
        return list(self.nodes.values()), self.edges

    # ---- stage stubs: each documents the exact call + edge(s) it produces ----

    def _collect_users_and_groups(self):
        # users = self.graph_client.users.get()
        # groups = self.graph_client.groups.get()
        # for each group: members -> MEMBER_OF edges
        raise NotImplementedError("Wire up Microsoft Graph /users and /groups calls")

    def _collect_service_principals(self):
        # sps = self.graph_client.service_principals.get()
        # -> NodeType.SERVICE_ACCOUNT nodes; flag appRoleAssignments with
        #    high-privilege Graph app roles (e.g. RoleManagement.ReadWrite.Directory)
        raise NotImplementedError("Wire up Microsoft Graph /servicePrincipals calls")

    def _collect_app_registrations(self):
        # apps = self.graph_client.applications.get()
        # -> NodeType.APP_REGISTRATION nodes + requiredResourceAccess parsing
        raise NotImplementedError("Wire up Microsoft Graph /applications calls")

    def _collect_directory_role_assignments(self):
        # roles = self.graph_client.role_management.directory.role_assignments.get()
        # -> for principals in HIGH_PRIV_AAD_ROLES, set is_admin=True and
        #    emit CAN_ATTACH_POLICY self-loop (same pattern as AWS collector)
        raise NotImplementedError("Wire up /roleManagement/directory/roleAssignments")

    def _collect_rbac_role_assignments(self):
        # Use azure-mgmt-authorization RoleAssignmentsOperations.list_for_subscription
        # -> for principals in HIGH_PRIV_RBAC_ROLES scoped at subscription or RG,
        #    set is_admin=True (Owner) or CAN_ATTACH_POLICY (User Access Admin)
        raise NotImplementedError("Wire up ARM roleAssignments for the subscription")
