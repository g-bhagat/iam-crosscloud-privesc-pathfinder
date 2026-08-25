## ---------------------------------------------------------------------------
## GCP Workload Identity Federation -- this file is where Pattern 2's actual
## vulnerability lives (docs/THREAT_MODEL.md). Both providers are AWS-type
## (an `aws { account_id = ... }` block, NOT `oidc { issuer_uri = ... }`) --
## GCP trusting an AWS account directly, no third-party OIDC issuer involved
## anywhere. One pool, two providers:
##
##   - "loose"  (planted misconfig): NO attribute_condition at all. The
##     provider-level `account_id` restriction is real narrowing (only this
##     one AWS account can reach it), but it's account-WIDE -- any IAM
##     principal in that account that can sign a valid AWS request can
##     obtain a token for this provider, not just track2-test-role. Bound to
##     a service account with roles/owner.
##   - "scoped" (negative control): attribute_condition pins the specific
##     assumed-role ARN via assertion.arn.startsWith(...), stopping exactly
##     at the role name. Bound to a minimally privileged service account.
##     The tool must NOT flag this binding as an escalation path.
## ---------------------------------------------------------------------------

locals {
  required_apis = [
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ]
}

resource "google_project_service" "required" {
  for_each = var.enable_gcp_apis ? toset(local.required_apis) : []

  project = var.gcp_project_id
  service = each.value

  # Don't disable a shared project API out from under other tooling just
  # because this sandbox config gets destroyed.
  disable_on_destroy = false
}

resource "google_iam_workload_identity_pool" "aws_direct" {
  workload_identity_pool_id = var.wif_pool_id
  display_name              = "Track 2 AWS-direct pool"
  description               = "Holds the Track 2 account-only-scoped + role-scoped AWS-type WIF providers. See docs/THREAT_MODEL.md Pattern 2."

  depends_on = [google_project_service.required]
}

# --- The planted misconfiguration --------------------------------------------

resource "google_iam_workload_identity_pool_provider" "loose" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.aws_direct.workload_identity_pool_id
  workload_identity_pool_provider_id = "aws-account-only"
  display_name                       = "Account-only AWS trust (PLANTED MISCONFIG)"
  description                        = "No attribute_condition -- accepts ANY principal in the trusted AWS account, not just track2-test-role. Do not copy this pattern."

  # GCP's AWS-type provider has NO default attribute.account mapping --
  # only google.subject = assertion.arn applies by default, and specifying
  # ANY custom attribute_mapping replaces the default rather than extending
  # it. Both keys are required here for the loose binding below to have an
  # "attribute.account" path to match against at all.
  attribute_mapping = {
    "google.subject"    = "assertion.arn"
    "attribute.account" = "assertion.account"
  }

  # THE VULNERABILITY: no attribute_condition at all. Compare to the
  # "scoped" provider below, whose attribute_condition pins one specific
  # role.
  aws {
    account_id = data.aws_caller_identity.current.account_id
  }

  depends_on = [google_iam_workload_identity_pool.aws_direct]
}

resource "google_service_account" "owner_target" {
  account_id   = var.owner_service_account_id
  display_name = "Track 2 target SA (roles/owner) -- reachable via the account-only-scoped AWS provider"
}

resource "google_project_iam_member" "owner_target_is_owner" {
  project = var.gcp_project_id
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.owner_target.email}"
}

# Grants the ENTIRE AWS-account-scoped principal set from the loose provider
# the ability to impersonate the owner-privileged SA. Member path is
# attribute.account -- NOT attribute.aws_account, which doesn't exist on
# this provider's attribute_mapping and would leave the binding silently
# matching nothing at all.
resource "google_service_account_iam_member" "loose_binding" {
  service_account_id = google_service_account.owner_target.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.aws_direct.name}/attribute.account/${data.aws_caller_identity.current.account_id}"
}

# --- The negative control -----------------------------------------------------

resource "google_iam_workload_identity_pool_provider" "scoped" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.aws_direct.workload_identity_pool_id
  workload_identity_pool_provider_id = "aws-role-scoped"
  display_name                       = "Role-scoped AWS trust (negative control)"
  description                        = "attribute_condition pins the specific assumed-role ARN. Must NOT be flagged by the escalation rule engine."

  attribute_mapping = {
    "google.subject"    = "assertion.arn"
    "attribute.account" = "assertion.account"
  }

  # The control: pinned to one specific role via startsWith(), stopping
  # exactly at the role name with no session-name component --
  # confidence.py's score_gcp_condition() HIGH-confidence regex is
  # assumed-role/[^/]+/?$, matching "assumed-role/<role-name>/" exactly.
  # Adding a session-name segment here would break that match and score
  # this MEDIUM instead of HIGH.
  attribute_condition = "assertion.arn.startsWith('arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${var.aws_test_role_name}/')"

  aws {
    account_id = data.aws_caller_identity.current.account_id
  }

  depends_on = [google_iam_workload_identity_pool.aws_direct]
}

resource "google_service_account" "scoped_target" {
  account_id   = var.scoped_service_account_id
  display_name = "Track 2 negative-control target SA (minimal privilege)"
}

resource "google_project_iam_member" "scoped_target_is_viewer" {
  project = var.gcp_project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.scoped_target.email}"
}

# This binding needs the FULL ARN, session name included -- google.subject's
# default mapping on an AWS-type provider is the complete assertion.arn, and
# principal:// (unlike principalSet://) matches exactly one literal subject
# value. That's why var.aws_session_name is fixed: the PoC always assumes
# track2-test-role with this exact --role-session-name, so the resulting
# assertion.arn always matches this binding. This is a TIGHTER, more
# specific match than the provider-level attribute_condition above, which
# only needs to stop at the role name.
resource "google_service_account_iam_member" "scoped_binding" {
  service_account_id = google_service_account.scoped_target.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.aws_direct.name}/subject/arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${var.aws_test_role_name}/${var.aws_session_name}"
}
