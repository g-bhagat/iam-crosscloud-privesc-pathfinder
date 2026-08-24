"""
Integration test: real AWSCollector output (moto-mocked, not hand-crafted)
flowing through correlation.py + escalation_rules.py. Closes a gap flagged
in review -- until now, tasks 9/10 had only ever been exercised against
sample_data/sample_graph.json, a hand-built fixture, never actual collector
output. GCPCollector (task 8) is still a stub, so the GCP side here is a
minimal synthetic stand-in for what it's expected to produce (per the
design note in gcp_collector.py) -- but the AWS side is 100% real
AWSCollector.collect() output, including the OIDC-provider condition-bug
fix this same change made.
"""

import json

import boto3
from moto import mock_aws

from src.analysis.confidence import Confidence
from src.analysis.correlation import correlate
from src.analysis.escalation_rules import run_all
from src.collectors.aws_collector import AWSCollector
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
