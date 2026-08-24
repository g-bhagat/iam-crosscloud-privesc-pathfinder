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
