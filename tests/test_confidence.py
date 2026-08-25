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


def test_aws_google_oidc_subject_id_pinned_is_high():
    """Track 3 shape (real data, not synthetic): AWS trusting Google's
    OIDC issuer, StringEquals-scoped to one specific GCP principal's
    Google subject ID under the accounts.google.com:sub key. Previously
    scored MEDIUM -- the HIGH-confidence checks above only recognized
    GitHub's repo:org/repo:ref:... shape and a bare 12-digit AWS account
    ID, not Google's long numeric subject ID."""
    condition = json.dumps(
        {
            "StringEquals": {
                "accounts.google.com:oaud": "https://sts.amazonaws.com/track3-role",
                "accounts.google.com:sub": "112233445566778899001",
            }
        }
    )
    assert score_aws_condition(condition) == Confidence.HIGH


def test_aws_long_numeric_value_without_sub_key_is_not_treated_as_pin():
    """The 15+ digit check is gated on the *:sub key specifically -- a
    long numeric condition value under some unrelated key must not, by
    digit count alone, be treated as a subject-ID pin."""
    condition = json.dumps({"StringEquals": {"accounts.google.com:some_other_claim": "112233445566778899001"}})
    assert score_aws_condition(condition) == Confidence.MEDIUM


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
