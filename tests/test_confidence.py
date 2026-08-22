import json

from src.analysis.confidence import Confidence, score_aws_condition, score_gcp_condition


def test_aws_repo_and_ref_pinned_is_high():
    condition = json.dumps(
        {
            "StringEquals": {
                "token.actions.githubusercontent.com:sub": "repo:acme-corp/victim-pipeline:ref:refs/heads/main",
            }
        }
    )
    assert score_aws_condition(condition) == Confidence.HIGH


def test_aws_repo_wildcard_is_medium():
    condition = json.dumps({"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme-corp/*"}})
    assert score_aws_condition(condition) == Confidence.MEDIUM


def test_aws_missing_condition_is_low():
    assert score_aws_condition(None) == Confidence.LOW
    assert score_aws_condition("") == Confidence.LOW


def test_aws_malformed_json_is_low():
    assert score_aws_condition("{not valid json") == Confidence.LOW


def test_gcp_repo_and_ref_pinned_is_high():
    cond = 'assertion.repository == "acme-corp/victim-pipeline" && assertion.ref == "refs/heads/main"'
    assert score_gcp_condition(cond) == Confidence.HIGH


def test_gcp_org_only_is_medium():
    assert score_gcp_condition('assertion.repository_owner == "acme-corp"') == Confidence.MEDIUM


def test_gcp_aws_account_only_is_medium():
    assert score_gcp_condition('assertion.account == "123456789012"') == Confidence.MEDIUM


def test_gcp_role_arn_pinned_is_high():
    assert (
        score_gcp_condition('assertion.arn == "arn:aws:sts::123456789012:assumed-role/deploy-role/session"')
        == Confidence.HIGH
    )


def test_gcp_missing_condition_is_low():
    assert score_gcp_condition(None) == Confidence.LOW
    assert score_gcp_condition("   ") == Confidence.LOW
