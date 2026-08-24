"""
Integration test: real collector output (moto-mocked AWS, mock-client GCP
-- not hand-crafted sample data) flowing through correlation.py +
escalation_rules.py. Closes a gap flagged in review -- until now, tasks
9/10 had only ever been exercised against sample_data/sample_graph.json,
a hand-built fixture, never actual collector output.

test_real_aws_collector_output_produces_a_true_positive_finding pairs
real AWSCollector output with a minimal synthetic GCP stand-in (from
before GCPCollector, task 8, existed).

test_real_aws_and_real_gcp_collectors_produce_a_true_positive_finding is
the fuller version, added once GCPCollector was implemented: BOTH sides
are now real collector output -- moto-mocked AWSCollector and
mock-client GCPCollector (see tests/test_gcp_collector.py for why GCP
uses hand-built mocks rather than a moto-style full-service fake --
no such library exists for GCP).
"""

import json
from unittest.mock import MagicMock

import boto3
from moto import mock_aws

from src.analysis.confidence import Confidence
from src.analysis.correlation import correlate
from src.analysis.escalation_rules import run_all
from src.analysis.pathfinder import find_escalation_paths
from src.collectors.aws_collector import AWSCollector
from src.collectors.gcp_collector import GCPCollector
from src.graph_schema import Cloud, Edge, EdgeType, Node, NodeType

OIDC_ISSUER_HOST = "token.actions.githubusercontent.com"


def _gcp_side_stand_in(gcp_project: str) -> tuple[list[Node], list[Edge]]:
    """Minimal synthetic stand-in for GCPCollector output (still a stub --
    task 8), shaped per the design note in gcp_collector.py: one bridge
    node keyed by issuer_uri, one loosely-scoped FEDERATES_WITH edge into
    an over-privileged SA."""
    bridge_id = f"gcp:wif_bridge:https://{OIDC_ISSUER_HOST}"
    owner_sa_id = f"gcp:service_account:owner-sa@{gcp_project}.iam.gserviceaccount.com"
    nodes = [
        Node(id=bridge_id, type=NodeType.APP_REGISTRATION, cloud=Cloud.CROSS_CLOUD, name=f"https://{OIDC_ISSUER_HOST}", external_facing=True),
        Node(id=owner_sa_id, type=NodeType.SERVICE_ACCOUNT, cloud=Cloud.GCP, name="owner-sa", is_admin=True),
    ]
    edges = [
        Edge(
            source=bridge_id, target=owner_sa_id, type=EdgeType.FEDERATES_WITH, cloud=Cloud.CROSS_CLOUD,
            condition='assertion.repository_owner == "acme-corp"',
            evidence="Workload Identity Federation binding (synthetic GCP stand-in)",
        )
    ]
    return nodes, edges


def test_real_aws_collector_output_produces_a_true_positive_finding():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam")
        account_id = session.client("sts").get_caller_identity()["Account"]

        provider_arn = iam.create_open_id_connect_provider(
            Url=f"https://{OIDC_ISSUER_HOST}",
            ClientIDList=["sts.amazonaws.com"],
            ThumbprintList=["6938fd4d98bab03faadb97b34396831e3780aea1"],
        )["OpenIDConnectProviderArn"]

        trust_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": provider_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            f"{OIDC_ISSUER_HOST}:sub": "repo:acme-corp/victim-pipeline:ref:refs/heads/main"
                        }
                    },
                }
            ],
        }
        iam.create_role(RoleName="cicd-deploy-role", AssumeRolePolicyDocument=json.dumps(trust_doc))

        aws_nodes, aws_edges = AWSCollector(session, account_id=account_id).collect()

    gcp_nodes, gcp_edges = _gcp_side_stand_in(gcp_project="track1-sandbox-project")

    merged_nodes, merged_edges, advisories = correlate(aws_nodes + gcp_nodes, aws_edges + gcp_edges)

    # The AWS and GCP bridge nodes must have merged into one canonical node
    # -- proving merge_oidc_bridges() actually fires against a REAL
    # AWSCollector-produced node id ("federated:<oidc-provider-arn>"), not
    # just the hand-crafted sample_graph.json shape.
    canonical = [n for n in merged_nodes if n.id.startswith("cross_cloud:oidc_bridge:")]
    assert len(canonical) == 1
    assert canonical[0].name == OIDC_ISSUER_HOST

    federates = [e for e in merged_edges if e.type == EdgeType.FEDERATES_WITH]
    assert len(federates) == 2
    assert all(e.source == canonical[0].id for e in federates)

    # The AWS-side edge condition survived the collector -> correlation
    # pipeline and scores HIGH (repo+branch pinned) -- this is the bug
    # this change fixed: previously that condition never made it onto the
    # edge at all.
    aws_edge = next(e for e in federates if "cicd-deploy-role" in e.target)
    assert aws_edge.attributes["confidence"] == Confidence.HIGH.value

    result = run_all(merged_nodes, merged_edges)
    pattern1 = [f for f in result.findings if f.pattern_id == 1]
    assert len(pattern1) == 1
    assert "owner-sa" in pattern1[0].target_node
    assert not advisories, "a correctly-scoped real AWS edge must not be dropped as a LOW-confidence advisory"


def _execute(value):
    m = MagicMock()
    m.execute.return_value = value
    return m


def _real_gcp_collector_output(project_id: str, pool_name: str) -> tuple[list, list]:
    """Real GCPCollector output (mock-client, per tests/test_gcp_collector.py's
    approach), shaped exactly like the actual Track 1 sandbox: one pool,
    two providers (loose + scoped), bound to owner/scoped SAs."""
    owner_email = f"track1-owner-sa@{project_id}.iam.gserviceaccount.com"
    owner_resource = f"projects/{project_id}/serviceAccounts/{owner_email}"
    scoped_email = f"track1-scoped-sa@{project_id}.iam.gserviceaccount.com"
    scoped_resource = f"projects/{project_id}/serviceAccounts/{scoped_email}"

    loose_provider = {
        "name": f"{pool_name}/providers/gh-loose-org-scope",
        "attributeCondition": 'assertion.repository_owner == "acme-corp"',
        "attributeMapping": {"google.subject": "assertion.sub", "attribute.repository_owner": "assertion.repository_owner"},
        "oidc": {"issuerUri": f"https://{OIDC_ISSUER_HOST}"},
    }
    scoped_provider = {
        "name": f"{pool_name}/providers/gh-scoped-repo-branch",
        "attributeCondition": 'assertion.repository == "acme-corp/victim-pipeline" && assertion.ref == "refs/heads/main"',
        "attributeMapping": {"google.subject": "assertion.sub", "attribute.repository": "assertion.repository", "attribute.ref": "assertion.ref"},
        "oidc": {"issuerUri": f"https://{OIDC_ISSUER_HOST}"},
    }

    iam_client = MagicMock()
    projects = iam_client.projects.return_value

    locations = projects.locations.return_value
    wip = locations.workloadIdentityPools.return_value
    wip.list.return_value = _execute({"workloadIdentityPools": [{"name": pool_name}]})
    providers = wip.providers.return_value
    providers.list.return_value = _execute({"workloadIdentityPoolProviders": [loose_provider, scoped_provider]})

    sa = projects.serviceAccounts.return_value
    sa.list.return_value = _execute(
        {
            "accounts": [
                {"name": owner_resource, "email": owner_email, "uniqueId": "1"},
                {"name": scoped_resource, "email": scoped_email, "uniqueId": "2"},
            ]
        }
    )
    sa.list_next.return_value = None
    sa_policies = {
        owner_resource: {
            "bindings": [
                {
                    "role": "roles/iam.workloadIdentityUser",
                    "members": [f"principalSet://iam.googleapis.com/{pool_name}/attribute.repository_owner/acme-corp"],
                }
            ]
        },
        scoped_resource: {
            "bindings": [
                {
                    "role": "roles/iam.workloadIdentityUser",
                    "members": [f"principalSet://iam.googleapis.com/{pool_name}/attribute.ref/refs/heads/main"],
                }
            ]
        },
    }
    sa.getIamPolicy.side_effect = lambda resource: _execute(sa_policies.get(resource, {"bindings": []}))
    sa.keys.return_value.list.side_effect = lambda name, keyTypes: _execute({"keys": []})

    asset_client = MagicMock()
    project_owner_grant = _cai_owner_grant(project_id, owner_email)
    asset_client.search_all_iam_policies.return_value = [project_owner_grant]

    collector = GCPCollector(asset_client=asset_client, iam_client=iam_client, project_id=project_id)
    return collector.collect()


def _cai_owner_grant(project_id: str, owner_email: str):
    from google.cloud.asset_v1.types import assets as asset_types
    from google.iam.v1 import policy_pb2

    policy = policy_pb2.Policy(
        bindings=[policy_pb2.Binding(role="roles/owner", members=[f"serviceAccount:{owner_email}"])]
    )
    return asset_types.IamPolicySearchResult(
        resource=f"//cloudresourcemanager.googleapis.com/projects/{project_id}",
        policy=policy,
    )


def test_real_aws_and_real_gcp_collectors_produce_a_true_positive_finding():
    """Both sides now real collector output -- proves the full pipeline
    (two independent collectors -> correlation -> escalation rules ->
    pathfinder) end to end without any hand-crafted graph anywhere."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam")
        account_id = session.client("sts").get_caller_identity()["Account"]

        provider_arn = iam.create_open_id_connect_provider(
            Url=f"https://{OIDC_ISSUER_HOST}",
            ClientIDList=["sts.amazonaws.com"],
            ThumbprintList=["6938fd4d98bab03faadb97b34396831e3780aea1"],
        )["OpenIDConnectProviderArn"]
        trust_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": provider_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {f"{OIDC_ISSUER_HOST}:sub": "repo:acme-corp/victim-pipeline:ref:refs/heads/main"}
                    },
                }
            ],
        }
        iam.create_role(RoleName="cicd-deploy-role", AssumeRolePolicyDocument=json.dumps(trust_doc))
        aws_nodes, aws_edges = AWSCollector(session, account_id=account_id).collect()

    gcp_project_id = "iam-pathfinder-sandbox"
    pool_name = "projects/111122223333/locations/global/workloadIdentityPools/github-actions-pool"
    gcp_nodes, gcp_edges = _real_gcp_collector_output(gcp_project_id, pool_name)

    merged_nodes, merged_edges, advisories = correlate(aws_nodes + gcp_nodes, aws_edges + gcp_edges)
    assert not advisories

    canonical = [n for n in merged_nodes if n.id.startswith("cross_cloud:oidc_bridge:")]
    assert len(canonical) == 1

    result = run_all(merged_nodes, merged_edges)
    pattern1_targets = {f.target_node for f in result.findings if f.pattern_id == 1}
    owner_id = next(n.id for n in merged_nodes if "track1-owner-sa" in n.name)
    scoped_id = next(n.id for n in merged_nodes if "track1-scoped-sa" in n.name)

    # True positive: the loose-provider binding reaches the roles/owner SA.
    assert owner_id in pattern1_targets
    # True negative: the scoped, correctly-condition-pinned binding to the
    # roles/viewer SA must NOT be flagged, even though it's structurally
    # the same kind of edge.
    assert scoped_id not in pattern1_targets

    paths = find_escalation_paths(merged_nodes, merged_edges, external_facing_only=True)
    assert any(p.target == owner_id for p in paths)
    assert not any(p.target == scoped_id for p in paths)
