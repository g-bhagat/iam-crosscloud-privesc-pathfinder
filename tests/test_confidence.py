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


def test_gcp_real_track2_loose_condition_is_medium_not_low():
    """Real bug, empirically confirmed against actual Track 2 infra: the
    real planted-misconfiguration provider sets NO attribute_condition at
    all, relying entirely on the provider's own --account-id restriction
    (a GCP AWS-type WIF provider is always scoped to exactly one AWS
    account at the provider level -- that field is mandatory). Previously
    this hit the empty-condition early return and scored LOW,
    indistinguishable from "no evidence of scoping at all" -- and
    tag_confidence() drops LOW edges from the traversal graph entirely,
    so Track 2's real, live-tested true positive was invisible."""
    assert score_gcp_condition(None, aws_account_id="123456789012") == Confidence.MEDIUM
    assert score_gcp_condition("", aws_account_id="123456789012") == Confidence.MEDIUM


def test_gcp_aws_account_id_without_condition_context_stays_low():
    """Without aws_account_id, an empty condition still means "no
    evidence of scoping at all" -- the floor only applies when the
    caller actually knows the provider is account-scoped."""
    assert score_gcp_condition(None) == Confidence.LOW
    assert score_gcp_condition("") == Confidence.LOW


def test_gcp_real_track2_scoped_role_arn_startswith_is_high():
    """Real bug: the real Track 2 negative control uses the standard
    startsWith() idiom to pin a specific AWS role
    (assertion.arn.startsWith('arn:aws:sts::<account>:assumed-role/
    <role>/')), not assertion.arn == '...' -- an STS assumed-role ARN's
    session-name suffix is dynamic per-assumption, so `==` can never
    match one. Previously fell through every HIGH/MEDIUM branch (no
    pattern for `.startsWith(`) all the way to LOW, exactly like the
    loose true positive -- the tool could not distinguish Track 2's true
    positive from its true negative at all."""
    cond = "assertion.arn.startsWith('arn:aws:sts::123456789012:assumed-role/track2-test-role/')"
    assert score_gcp_condition(cond) == Confidence.HIGH
    # Still HIGH even with aws_account_id passed -- a role-level pin is
    # never downgraded by the account-level floor.
    assert score_gcp_condition(cond, aws_account_id="123456789012") == Confidence.HIGH


def test_gcp_account_only_arn_startswith_prefix_is_medium():
    """A startsWith() prefix that stops at the assumed-role/ boundary
    with no role name after it only narrows to the account -- same
    confidence tier as an explicit assertion.account == '...' check, not
    a role-level pin."""
    cond = "assertion.arn.startsWith('arn:aws:sts::123456789012:assumed-role/')"
    assert score_gcp_condition(cond) == Confidence.MEDIUM
