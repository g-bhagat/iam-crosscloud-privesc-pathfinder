## ---------------------------------------------------------------------------
## GCP side of Track 3 (docs/THREAT_MODEL.md Pattern 3) -- deliberately
## minimal. track3_ordinary is NOT itself over-privileged in GCP; the whole
## point is that it looks unremarkable from GCP's own perspective. Its
## escalation path exists entirely on the AWS side (aws.tf), which trusts
## Google's built-in issuer (accounts.google.com) too broadly -- a GCP-only
## tool has no way to know this SA can become an AWS admin, and an AWS-only
## tool would need to already know which GCP principal to look for.
## ---------------------------------------------------------------------------

locals {
  required_apis = [
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
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

resource "google_service_account" "track3_ordinary" {
  account_id   = var.ordinary_service_account_id
  display_name = "Track 3 ordinary-looking SA"
  description  = "No notable GCP permissions of its own -- the point is it looks unremarkable from GCP's own perspective. See aws.tf for where its actual escalation path lives."

  depends_on = [google_project_service.required]
}

# The currently-authenticated Terraform-applying identity -- used below so
# the PoC (README.md) works without a manual extra IAM step.
data "google_client_openid_userinfo" "operator" {}

# Lets the operator generate identity tokens AS track3_ordinary via
# `gcloud auth print-identity-token --impersonate-service-account=...`
# (the PoC in README.md) without a separate manual grant. If you're
# applying this config as a GCP service account rather than a human user,
# change "user:" to "serviceAccount:" below.
resource "google_service_account_iam_member" "operator_can_impersonate" {
  service_account_id = google_service_account.track3_ordinary.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "user:${data.google_client_openid_userinfo.operator.email}"
}
