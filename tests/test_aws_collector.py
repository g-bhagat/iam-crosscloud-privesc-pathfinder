"""
Unit tests for AWSCollector, mocked entirely via moto -- no live AWS
credentials or sandbox account needed. This is what lets task 9-12's
analysis layer be validated against *real collector output* (not just the
synthetic sample_graph.json fixture) before task 3 (a real AWS sandbox
account) exists.
"""

import json

import boto3
import pytest
from moto import mock_aws

from src.collectors.aws_collector import AWSCollector
from src.graph_schema import Cloud, EdgeType, NodeType
from src.visualization.pyvis_export import export_graph

OIDC_CREATE_URL = "https://token.actions.githubusercontent.com"
# AWS's real GetOpenIDConnectProvider API returns Url WITHOUT the scheme,
# regardless of what CreateOpenIDConnectProvider was given -- moto
# correctly replicates this. correlation.py's _oidc_host() strips the
# scheme for matching anyway, so a bare host is exactly the expected shape.
OIDC_ISSUER_HOST = "token.actions.githubusercontent.com"
ROLE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:sub": "repo:acme-corp/victim-pipeline:ref:refs/heads/main"
                }
            },
        }
    ],
}


@pytest.fixture
def aws_session():
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


@pytest.fixture
def account_id(aws_session):
    return aws_session.client("sts").get_caller_identity()["Account"]


def _create_oidc_provider(aws_session):
    iam = aws_session.client("iam")
    resp = iam.create_open_id_connect_provider(
        Url=OIDC_CREATE_URL,
        ClientIDList=["sts.amazonaws.com"],
        ThumbprintList=["6938fd4d98bab03faadb97b34396831e3780aea1"],
    )
    return resp["OpenIDConnectProviderArn"]


def test_collects_oidc_provider_with_metadata(aws_session, account_id):
    provider_arn = _create_oidc_provider(aws_session)

    collector = AWSCollector(aws_session, account_id=account_id)
    nodes, _edges = collector.collect()

    bridge_id = f"federated:{provider_arn}"
    matches = [n for n in nodes if n.id == bridge_id]
    assert len(matches) == 1, "OIDC provider must produce exactly one node, not a duplicate"

    node = matches[0]
    assert node.type == NodeType.APP_REGISTRATION
    assert node.cloud == Cloud.CROSS_CLOUD
    assert node.external_facing is True
    assert node.attributes["issuer_url"] == OIDC_ISSUER_HOST
    assert node.attributes["client_id_list"] == ["sts.amazonaws.com"]
    assert node.attributes["thumbprint_list"] == ["6938fd4d98bab03faadb97b34396831e3780aea1"]
    assert node.attributes["arn"] == provider_arn


def test_provider_not_referenced_by_any_role_still_surfaces(aws_session, account_id):
    """The gap the task described: a provider that exists but that no
    role's trust policy currently references was previously invisible."""
    provider_arn = _create_oidc_provider(aws_session)

    collector = AWSCollector(aws_session, account_id=account_id)
    nodes, edges = collector.collect()

    bridge_id = f"federated:{provider_arn}"
    assert any(n.id == bridge_id for n in nodes)
    # No role trusts it yet, so no FEDERATES_WITH edge should exist for it.
    assert not any(e.source == bridge_id and e.type == EdgeType.FEDERATES_WITH for e in edges)


def test_provider_referenced_by_role_gets_enriched_not_duplicated(aws_session, account_id):
    """The node _parse_trust_policy creates from a role's Federated
    principal and the node _collect_oidc_providers creates from listing
    the provider resource directly must be the SAME node, carrying both
    the FEDERATES_WITH edge and the provider metadata."""
    provider_arn = _create_oidc_provider(aws_session)
    iam = aws_session.client("iam")
    trust_doc = json.loads(json.dumps(ROLE_TRUST_POLICY).replace("{account}", account_id))
    iam.create_role(RoleName="cicd-deploy-role", AssumeRolePolicyDocument=json.dumps(trust_doc))

    collector = AWSCollector(aws_session, account_id=account_id)
    nodes, edges = collector.collect()

    bridge_id = f"federated:{provider_arn}"
    matches = [n for n in nodes if n.id == bridge_id]
    assert len(matches) == 1, "trust-policy parsing and direct provider listing must land on one node"

    node = matches[0]
    # Metadata from _collect_oidc_providers is present...
    assert node.attributes["issuer_url"] == OIDC_ISSUER_HOST
    # ...and the FEDERATES_WITH edge from _parse_trust_policy is present too.
    federates = [e for e in edges if e.source == bridge_id and e.type == EdgeType.FEDERATES_WITH]
    assert len(federates) == 1
    assert federates[0].target.endswith("cicd-deploy-role")
    assert federates[0].condition is not None


def test_collect_handles_zero_oidc_providers(aws_session, account_id):
    """No providers configured at all -- must not raise."""
    collector = AWSCollector(aws_session, account_id=account_id)
    nodes, _edges = collector.collect()
    assert not any(n.id.startswith("federated:") for n in nodes)


def test_aws_managed_policy_attachment_gets_a_real_node_and_edge(monkeypatch, tmp_path):
    """Regression test for a real bug: _collect_identity_policies() created
    a HAS_POLICY edge for every attached policy, but only
    _collect_managed_policies() created policy NODES -- and only for
    Scope="Local" (customer-managed) policies. An AWS-managed policy (the
    kind every service-linked role has by design, and the one used here,
    AdministratorAccess) got an edge pointing at a node that was never
    created. pyvis_export correctly drops an edge with a missing endpoint
    at render time, but _nodes_with_any_edge() doesn't check node
    existence -- so the role would still count as "connected" and survive
    isolated-node filtering while rendering with zero actual edges,
    indistinguishable from a genuinely isolated node without being
    flagged as one.

    Uses a real AWS-managed policy ARN (not moto's default-empty managed
    policy catalog) via MOTO_IAM_LOAD_MANAGED_POLICIES=true, confirmed
    against the installed moto version's settings.py.
    """
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        account_id = session.client("sts").get_caller_identity()["Account"]
        iam = session.client("iam")
        iam.create_role(
            RoleName="managed-only-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )
        iam.attach_role_policy(RoleName="managed-only-role", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")

        collector = AWSCollector(session, account_id=account_id)
        nodes, edges = collector.collect()

        role_id = next(n.id for n in nodes if n.name == "managed-only-role")
        policy_node = next((n for n in nodes if n.type == NodeType.POLICY and n.name == "AdministratorAccess"), None)
        assert policy_node is not None, "AWS-managed attached policy must get a real node, not just an edge target"
        assert policy_node.attributes["arn"] == "arn:aws:iam::aws:policy/AdministratorAccess"

        has_policy_edges = [e for e in edges if e.source == role_id and e.type == EdgeType.HAS_POLICY]
        assert len(has_policy_edges) == 1
        assert has_policy_edges[0].target == policy_node.id

        # Both endpoints are real nodes -- the edge is genuinely renderable,
        # not silently dropped by pyvis_export's missing-endpoint check.
        node_ids = {n.id for n in nodes}
        assert has_policy_edges[0].source in node_ids
        assert has_policy_edges[0].target in node_ids

        # And it shows up that way through the actual render pipeline, not
        # just in the raw node/edge lists: not hidden by the default
        # isolated-node filter, and its HAS_POLICY edge to the policy node
        # is present in the output.
        out_path = export_graph(nodes, edges, tmp_path / "graph.html")
        html = out_path.read_text()
        assert "managed-only-role" in html
        assert "AdministratorAccess" in html
