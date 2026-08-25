"""
Unit tests for GCPCollector. No live GCP credentials or project needed --
GCP doesn't have a moto-equivalent full-service mock, so instead:

- asset_client is faked with real google.cloud.asset_v1.types objects
  (IamPolicySearchResult wrapping a real google.iam.v1.policy_pb2.Policy),
  constructed directly against the actual installed client library's
  message classes -- not hand-guessed dicts.
- iam_client is faked with unittest.mock, wired to return response dicts
  shaped exactly like the real IAM Admin API v1 REST responses (verified
  against googleapiclient's bundled iam.v1 discovery document and its
  method docstrings -- see the shapes confirmed for
  serviceAccounts().list/getIamPolicy/keys().list and
  workloadIdentityPools()/providers().list before this test was written).

Fixture data mirrors the real Track 1 sandbox described in the task that
added this collector: pool "github-actions-pool" with providers
"gh-loose-org-scope" (planted misconfiguration) and
"gh-scoped-repo-branch" (negative control), bound to track1-owner-sa
(roles/owner) and track1-scoped-sa (roles/viewer) respectively. Live
validation against the actual project happens separately, outside this
sandboxed session -- see scripts/run_gcp_collector.py.
"""

from unittest.mock import MagicMock

import pytest
from google.cloud.asset_v1.types import assets as asset_types
from google.iam.v1 import policy_pb2

from src.collectors.gcp_collector import GCPCollector
from src.graph_schema import Cloud, EdgeType, NodeType

PROJECT_ID = "iam-pathfinder-sandbox"
PROJECT_NUMBER = "111122223333"
POOL_NAME = f"projects/{PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions-pool"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"

OWNER_SA_EMAIL = f"track1-owner-sa@{PROJECT_ID}.iam.gserviceaccount.com"
OWNER_SA_RESOURCE = f"projects/{PROJECT_ID}/serviceAccounts/{OWNER_SA_EMAIL}"
SCOPED_SA_EMAIL = f"track1-scoped-sa@{PROJECT_ID}.iam.gserviceaccount.com"
SCOPED_SA_RESOURCE = f"projects/{PROJECT_ID}/serviceAccounts/{SCOPED_SA_EMAIL}"

LOOSE_PROVIDER = {
    "name": f"{POOL_NAME}/providers/gh-loose-org-scope",
    "attributeCondition": 'assertion.repository_owner == "acme-corp"',
    "attributeMapping": {
        "google.subject": "assertion.sub",
        "attribute.repository": "assertion.repository",
        "attribute.repository_owner": "assertion.repository_owner",
    },
    "oidc": {"issuerUri": OIDC_ISSUER},
}
SCOPED_PROVIDER = {
    "name": f"{POOL_NAME}/providers/gh-scoped-repo-branch",
    "attributeCondition": 'assertion.repository == "acme-corp/victim-pipeline" && assertion.ref == "refs/heads/main"',
    "attributeMapping": {
        "google.subject": "assertion.sub",
        "attribute.repository": "assertion.repository",
        "attribute.ref": "assertion.ref",
    },
    "oidc": {"issuerUri": OIDC_ISSUER},
}


def _execute(value):
    """A mock 'request' object whose .execute() returns `value`, matching
    googleapiclient's HttpRequest interface."""
    m = MagicMock()
    m.execute.return_value = value
    return m


def _build_iam_client(
    *,
    pools=None,
    providers_by_pool=None,
    service_accounts=None,
    sa_policies=None,
    sa_keys=None,
):
    pools = pools if pools is not None else []
    providers_by_pool = providers_by_pool or {}
    service_accounts = service_accounts if service_accounts is not None else []
    sa_policies = sa_policies or {}
    sa_keys = sa_keys or {}

    iam = MagicMock()
    projects = iam.projects.return_value

    locations = projects.locations.return_value
    wip = locations.workloadIdentityPools.return_value
    wip.list.return_value = _execute({"workloadIdentityPools": pools})
    providers = wip.providers.return_value
    providers.list.side_effect = lambda parent: _execute(
        {"workloadIdentityPoolProviders": providers_by_pool.get(parent, [])}
    )

    sa = projects.serviceAccounts.return_value
    sa.list.return_value = _execute({"accounts": service_accounts})
    sa.list_next.return_value = None  # single page in every test fixture
    sa.getIamPolicy.side_effect = lambda resource: _execute(sa_policies.get(resource, {"bindings": []}))
    keys = sa.keys.return_value
    keys.list.side_effect = lambda name, keyTypes: _execute(sa_keys.get(name, {"keys": []}))

    return iam


def _cai_result(resource: str, bindings: list[tuple[str, list[str]]], asset_type: str = "") -> asset_types.IamPolicySearchResult:
    policy = policy_pb2.Policy(bindings=[policy_pb2.Binding(role=role, members=members) for role, members in bindings])
    return asset_types.IamPolicySearchResult(resource=resource, asset_type=asset_type, policy=policy)


@pytest.fixture
def sa_list():
    return [
        {
            "name": OWNER_SA_RESOURCE,
            "email": OWNER_SA_EMAIL,
            "uniqueId": "100000000000000000001",
            "displayName": "Track 1 owner target SA",
        },
        {
            "name": SCOPED_SA_RESOURCE,
            "email": SCOPED_SA_EMAIL,
            "uniqueId": "100000000000000000002",
            "displayName": "Track 1 scoped negative-control SA",
        },
    ]


@pytest.fixture
def pools():
    return [{"name": POOL_NAME, "displayName": "GitHub Actions pool"}]


@pytest.fixture
def providers_by_pool():
    return {POOL_NAME: [LOOSE_PROVIDER, SCOPED_PROVIDER]}


def test_service_accounts_collected_as_nodes(sa_list):
    iam_client = _build_iam_client(service_accounts=sa_list)
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, _edges = collector.collect()

    sa_nodes = {n.name: n for n in nodes if n.type == NodeType.SERVICE_ACCOUNT}
    assert set(sa_nodes) == {OWNER_SA_EMAIL, SCOPED_SA_EMAIL}
    assert sa_nodes[OWNER_SA_EMAIL].cloud == Cloud.GCP
    assert sa_nodes[OWNER_SA_EMAIL].attributes["resource_name"] == OWNER_SA_RESOURCE


def test_user_managed_key_flags_external_facing(sa_list):
    iam_client = _build_iam_client(
        service_accounts=sa_list,
        sa_keys={SCOPED_SA_RESOURCE: {"keys": [{"name": f"{SCOPED_SA_RESOURCE}/keys/abc123", "keyType": "USER_MANAGED"}]}},
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, _edges = collector.collect()

    by_name = {n.name: n for n in nodes if n.type == NodeType.SERVICE_ACCOUNT}
    assert by_name[SCOPED_SA_EMAIL].external_facing is True
    assert by_name[SCOPED_SA_EMAIL].attributes["user_managed_key_count"] == 1
    assert by_name[OWNER_SA_EMAIL].external_facing is False


def test_workload_identity_pools_create_one_shared_bridge_node(pools, providers_by_pool):
    iam_client = _build_iam_client(pools=pools, providers_by_pool=providers_by_pool)
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, _edges = collector.collect()

    bridges = [n for n in nodes if n.id == f"gcp:wif_bridge:{OIDC_ISSUER}"]
    assert len(bridges) == 1, "both providers share one issuer -- must produce ONE bridge node, not two"
    assert bridges[0].cloud == Cloud.CROSS_CLOUD
    assert bridges[0].external_facing is True


def test_disabled_provider_is_skipped(pools):
    disabled = dict(LOOSE_PROVIDER, disabled=True)
    iam_client = _build_iam_client(pools=pools, providers_by_pool={POOL_NAME: [disabled]})
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, _edges = collector.collect()
    assert not any(n.id == f"gcp:wif_bridge:{OIDC_ISSUER}" for n in nodes)


def test_true_positive_loose_binding_produces_federates_with_edge_with_raw_condition(sa_list, pools, providers_by_pool):
    """The exact Track 1 mechanism: track1-owner-sa's workloadIdentityUser
    binding references attribute.repository_owner -- only the loose
    provider maps that attribute, so the edge must carry THAT provider's
    raw attributeCondition string, unmodified."""
    iam_client = _build_iam_client(
        pools=pools,
        providers_by_pool=providers_by_pool,
        service_accounts=sa_list,
        sa_policies={
            OWNER_SA_RESOURCE: {
                "bindings": [
                    {
                        "role": "roles/iam.workloadIdentityUser",
                        "members": [f"principalSet://iam.googleapis.com/{POOL_NAME}/attribute.repository_owner/acme-corp"],
                    }
                ]
            },
        },
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, edges = collector.collect()

    bridge_id = f"gcp:wif_bridge:{OIDC_ISSUER}"
    owner_sa_id = next(n.id for n in nodes if n.name == OWNER_SA_EMAIL)
    federates = [e for e in edges if e.type == EdgeType.FEDERATES_WITH and e.target == owner_sa_id]
    assert len(federates) == 1
    edge = federates[0]
    assert edge.source == bridge_id
    # Literal CEL string, byte-for-byte, not transformed or summarized.
    assert edge.condition == LOOSE_PROVIDER["attributeCondition"]
    assert "gh-loose-org-scope" in edge.evidence


def test_negative_control_scoped_binding_gets_its_own_provider_condition(sa_list, pools, providers_by_pool):
    iam_client = _build_iam_client(
        pools=pools,
        providers_by_pool=providers_by_pool,
        service_accounts=sa_list,
        sa_policies={
            SCOPED_SA_RESOURCE: {
                "bindings": [
                    {
                        "role": "roles/iam.workloadIdentityUser",
                        "members": [f"principalSet://iam.googleapis.com/{POOL_NAME}/attribute.ref/refs/heads/main"],
                    }
                ]
            },
        },
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, edges = collector.collect()

    scoped_sa_id = next(n.id for n in nodes if n.name == SCOPED_SA_EMAIL)
    federates = [e for e in edges if e.type == EdgeType.FEDERATES_WITH and e.target == scoped_sa_id]
    assert len(federates) == 1
    assert federates[0].condition == SCOPED_PROVIDER["attributeCondition"]
    assert "gh-scoped-repo-branch" in federates[0].evidence


def test_unresolvable_workload_identity_member_logs_and_does_not_crash(sa_list, pools, providers_by_pool, caplog):
    iam_client = _build_iam_client(
        pools=pools,
        providers_by_pool=providers_by_pool,
        service_accounts=sa_list,
        sa_policies={
            OWNER_SA_RESOURCE: {
                "bindings": [
                    {
                        "role": "roles/iam.workloadIdentityUser",
                        # No provider in this pool maps "attribute.nonexistent".
                        "members": [f"principalSet://iam.googleapis.com/{POOL_NAME}/attribute.nonexistent/x"],
                    }
                ]
            },
        },
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, edges = collector.collect()  # must not raise

    owner_sa_id = next(n.id for n in nodes if n.name == OWNER_SA_EMAIL)
    assert not any(e.type == EdgeType.FEDERATES_WITH and e.target == owner_sa_id for e in edges)


def test_token_creator_produces_can_impersonate_edge(sa_list):
    iam_client = _build_iam_client(
        service_accounts=sa_list,
        sa_policies={
            OWNER_SA_RESOURCE: {
                "bindings": [
                    {"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:alice@example.com"]},
                ]
            },
        },
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, edges = collector.collect()

    alice_id = "gcp:user:alice@example.com"
    owner_sa_id = next(n.id for n in nodes if n.name == OWNER_SA_EMAIL)
    assert any(n.id == alice_id for n in nodes)
    assert any(
        e.type == EdgeType.CAN_IMPERSONATE and e.source == alice_id and e.target == owner_sa_id for e in edges
    )


def test_human_user_node_gets_short_name_not_full_email(sa_list):
    """Readability fix: a NodeType.USER node for a human Google account
    previously used the FULL EMAIL as its `name` -- inconsistent with
    every other node type in the graph (short display label, full detail
    in `attributes`). The email's local part is now the name; the full
    email moves to attributes["email"]. Node `id` is unchanged (still the
    full email), so sanitize.py's human-email masking is unaffected --
    see test_sanitize.py for that half."""
    iam_client = _build_iam_client(
        service_accounts=sa_list,
        sa_policies={
            OWNER_SA_RESOURCE: {
                "bindings": [
                    {"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:gopilalbhagat9@gmail.com"]},
                ]
            },
        },
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, _edges = collector.collect()

    user_node = next(n for n in nodes if n.id == "gcp:user:gopilalbhagat9@gmail.com")
    assert user_node.name == "gopilalbhagat9", "must be the short local-part, not the full email"
    assert user_node.attributes["email"] == "gopilalbhagat9@gmail.com"


def test_service_account_user_produces_can_pass_role_edge(sa_list):
    iam_client = _build_iam_client(
        service_accounts=sa_list,
        sa_policies={
            OWNER_SA_RESOURCE: {
                "bindings": [
                    {"role": "roles/iam.serviceAccountUser", "members": ["group:deployers@example.com"]},
                ]
            },
        },
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, edges = collector.collect()

    group_id = "gcp:group:deployers@example.com"
    owner_sa_id = next(n.id for n in nodes if n.name == OWNER_SA_EMAIL)
    assert any(n.id == group_id and n.type == NodeType.GROUP for n in nodes)
    assert any(e.type == EdgeType.CAN_PASS_ROLE and e.source == group_id and e.target == owner_sa_id for e in edges)


def test_wif_member_on_token_creator_is_skipped_not_crashed(sa_list):
    """serviceAccountTokenCreator/serviceAccountUser granted directly to a
    WIF principalSet (not via workloadIdentityUser) is a narrower shape
    this collector doesn't resolve to a bridge -- must not crash, and
    must not silently fabricate a CAN_IMPERSONATE edge from a bridge."""
    iam_client = _build_iam_client(
        service_accounts=sa_list,
        sa_policies={
            OWNER_SA_RESOURCE: {
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": [f"principalSet://iam.googleapis.com/{POOL_NAME}/attribute.repository_owner/acme-corp"],
                    },
                ]
            },
        },
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, edges = collector.collect()  # must not raise

    owner_sa_id = next(n.id for n in nodes if n.name == OWNER_SA_EMAIL)
    assert not any(e.type == EdgeType.CAN_IMPERSONATE and e.target == owner_sa_id for e in edges)


def test_cai_project_level_owner_grant_flags_is_admin(sa_list):
    """This is how track1-owner-sa actually gets roles/owner in the real
    sandbox: a PROJECT-level binding (google_project_iam_member in
    Terraform), not anything on the SA's own IAM policy."""
    asset_client = MagicMock()
    asset_client.search_all_iam_policies.return_value = [
        _cai_result(
            resource=f"//cloudresourcemanager.googleapis.com/projects/{PROJECT_ID}",
            bindings=[("roles/owner", [f"serviceAccount:{OWNER_SA_EMAIL}"])],
            asset_type="cloudresourcemanager.googleapis.com/Project",
        )
    ]
    iam_client = _build_iam_client(service_accounts=sa_list)
    collector = GCPCollector(asset_client=asset_client, iam_client=iam_client, project_id=PROJECT_ID)
    nodes, edges = collector.collect()

    owner_node = next(n for n in nodes if n.name == OWNER_SA_EMAIL)
    assert owner_node.is_admin is True
    assert any(
        e.type == EdgeType.CAN_ATTACH_POLICY and e.source == owner_node.id and e.target == owner_node.id
        for e in edges
    )
    scoped_node = next(n for n in nodes if n.name == SCOPED_SA_EMAIL)
    assert scoped_node.is_admin is False


def test_cai_non_admin_role_does_not_flag_is_admin(sa_list):
    asset_client = MagicMock()
    asset_client.search_all_iam_policies.return_value = [
        _cai_result(
            resource=f"//cloudresourcemanager.googleapis.com/projects/{PROJECT_ID}",
            bindings=[("roles/viewer", [f"serviceAccount:{SCOPED_SA_EMAIL}"])],
        )
    ]
    iam_client = _build_iam_client(service_accounts=sa_list)
    collector = GCPCollector(asset_client=asset_client, iam_client=iam_client, project_id=PROJECT_ID)
    nodes, _edges = collector.collect()

    scoped_node = next(n for n in nodes if n.name == SCOPED_SA_EMAIL)
    assert scoped_node.is_admin is False


def test_collect_returns_empty_without_both_clients():
    assert GCPCollector(asset_client=None, iam_client=MagicMock(), project_id=PROJECT_ID).collect() == ([], [])
    assert GCPCollector(asset_client=MagicMock(), iam_client=None, project_id=PROJECT_ID).collect() == ([], [])


def test_failed_provider_list_for_one_pool_does_not_abort_collection(sa_list):
    """Two pools; providers().list() raises for the first, succeeds for
    the second -- collection must continue, not abort entirely."""
    other_pool = f"projects/{PROJECT_NUMBER}/locations/global/workloadIdentityPools/other-pool"
    iam_client = _build_iam_client(
        pools=[{"name": POOL_NAME}, {"name": other_pool}],
        service_accounts=sa_list,
    )
    providers = iam_client.projects.return_value.locations.return_value.workloadIdentityPools.return_value.providers.return_value

    def side_effect(parent):
        if parent == POOL_NAME:
            raise TimeoutError("simulated transient failure")
        return _execute({"workloadIdentityPoolProviders": [SCOPED_PROVIDER]})

    providers.list.side_effect = side_effect

    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, _edges = collector.collect()  # must not raise
    assert any(n.id == f"gcp:wif_bridge:{OIDC_ISSUER}" for n in nodes)


def test_aws_type_provider_registers_no_bridge_node(pools):
    aws_provider = {
        "name": f"{POOL_NAME}/providers/aws-account-only",
        "attributeCondition": None,
        "attributeMapping": {"google.subject": "assertion.arn"},
        "aws": {"accountId": "999988887777"},
    }
    iam_client = _build_iam_client(pools=pools, providers_by_pool={POOL_NAME: [aws_provider]})
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, _edges = collector.collect()

    assert not any(n.cloud == Cloud.CROSS_CLOUD and n.id.startswith("gcp:wif_bridge:") for n in nodes)


AWS_ACCOUNT_ID = "999988887777"
AWS_ACCOUNT_PROVIDER = {
    "name": f"{POOL_NAME}/providers/aws-account-only",
    # Account-only scoping -- Track 2's actual planted misconfiguration:
    # real federation, but the trusted principal is "anyone in this AWS
    # account," not one specific role.
    "attributeCondition": f'assertion.account == "{AWS_ACCOUNT_ID}"',
    "attributeMapping": {"google.subject": "assertion.arn"},
    "aws": {"accountId": AWS_ACCOUNT_ID},
}


def test_aws_type_provider_produces_federates_with_edge_from_synthetic_account_node(sa_list, pools):
    """Regression test for a real bug: an AWS-type provider (Track 2's
    actual mechanism -- a GCP WIF pool trusting an AWS account directly,
    no third-party OIDC issuer involved) previously made
    _emit_workload_identity_edge emit NOTHING at all, on the theory that
    correlation.py's merge_direct_references() would resolve it later --
    but that function only ever rewrites an edge that already exists, it
    never creates one from scratch. Confirmed against real Track 2
    infrastructure (proven working via a live AWS->GCP token exchange):
    zero edges, zero findings, zero paths.

    Must now produce a real FEDERATES_WITH edge from a synthetic "any AWS
    principal in this account" node to the target SA, carrying the raw
    account-only attribute_condition unchanged.
    """
    iam_client = _build_iam_client(
        pools=pools,
        providers_by_pool={POOL_NAME: [AWS_ACCOUNT_PROVIDER]},
        service_accounts=sa_list,
        sa_policies={
            OWNER_SA_RESOURCE: {
                "bindings": [
                    {
                        "role": "roles/iam.workloadIdentityUser",
                        "members": [
                            f"principal://iam.googleapis.com/{POOL_NAME}/subject/"
                            f"arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/gha-deployer/GitHubActions"
                        ],
                    }
                ]
            },
        },
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, edges = collector.collect()

    source_id = f"aws:external_account:{AWS_ACCOUNT_ID}"
    owner_sa_id = next(n.id for n in nodes if n.name == OWNER_SA_EMAIL)

    # The synthetic source node must actually exist as a real node -- an
    # edge pointing at a node that was never created is exactly the
    # AWS-managed-policy bug this codebase already fixed once
    # (aws_collector.py's _collect_identity_policies); don't repeat it.
    source_node = next((n for n in nodes if n.id == source_id), None)
    assert source_node is not None, "synthetic AWS account node must be a real node, not just an edge endpoint"
    assert source_node.cloud == Cloud.AWS
    assert source_node.external_facing is True
    assert source_node.attributes["aws_account_id"] == AWS_ACCOUNT_ID

    federates = [e for e in edges if e.type == EdgeType.FEDERATES_WITH and e.target == owner_sa_id]
    assert len(federates) == 1
    edge = federates[0]
    assert edge.source == source_id
    assert edge.condition == AWS_ACCOUNT_PROVIDER["attributeCondition"]
    assert edge.attributes["aws_account_id"] == AWS_ACCOUNT_ID


def test_aws_type_provider_with_no_condition_still_carries_account_id(sa_list, pools):
    """The REAL Track 2 loose misconfiguration, confirmed empirically
    against actual infrastructure: the provider sets NO
    attributeCondition at all, relying entirely on the provider's own
    --account-id restriction (mandatory when creating an AWS-type WIF
    provider) rather than an explicit CEL condition. The edge must still
    carry aws_account_id -- that's what lets confidence.py's
    score_gcp_condition() floor this to MEDIUM instead of LOW (see
    tests/test_confidence.py); without it on the edge, this exact real
    shape would score identically to "no evidence of scoping at all"."""
    provider = dict(AWS_ACCOUNT_PROVIDER, attributeCondition=None)
    iam_client = _build_iam_client(
        pools=pools,
        providers_by_pool={POOL_NAME: [provider]},
        service_accounts=sa_list,
        sa_policies={
            OWNER_SA_RESOURCE: {
                "bindings": [
                    {
                        "role": "roles/iam.workloadIdentityUser",
                        "members": [
                            f"principal://iam.googleapis.com/{POOL_NAME}/subject/"
                            f"arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/gha-deployer/GitHubActions"
                        ],
                    }
                ]
            },
        },
    )
    collector = GCPCollector(asset_client=MagicMock(), iam_client=iam_client, project_id=PROJECT_ID)
    nodes, edges = collector.collect()

    owner_sa_id = next(n.id for n in nodes if n.name == OWNER_SA_EMAIL)
    federates = [e for e in edges if e.type == EdgeType.FEDERATES_WITH and e.target == owner_sa_id]
    assert len(federates) == 1
    assert federates[0].condition is None
    assert federates[0].attributes["aws_account_id"] == AWS_ACCOUNT_ID
