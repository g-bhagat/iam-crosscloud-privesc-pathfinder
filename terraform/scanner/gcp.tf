## ---------------------------------------------------------------------------
## The GCP half of task 5: "Create a least-privilege, read-only scanning
## credential." This is the actual identity GCPCollector authenticates as
## (via impersonation, not a downloaded key -- see below), formalizing an
## identity already manually created and validated. The permission set
## matches exactly what src/collectors/gcp_collector.py's module docstring
## documents: roles/cloudasset.viewer for SearchAllIamPolicies, plus the IAM
## Admin API's serviceAccounts.list/get/getIamPolicy and
## workloadIdentityPools/-Providers.list -- the former covered by
## roles/iam.securityReviewer, the latter needing
## roles/iam.workloadIdentityPoolViewer separately (securityReviewer alone
## does not cover Workload Identity Pool/provider read access).
##
## Deliberately NO service account key resource anywhere in this file --
## SCOPE.md's stance is no long-lived credentials committed to this repo,
## ever, and more broadly this project authenticates via impersonation (ADC
## + serviceAccountTokenCreator), never a downloaded key, for exactly that
## reason. The google_service_account_iam_member below is what makes
## impersonation possible for a real human operator without ever creating
## one.
## ---------------------------------------------------------------------------

resource "google_service_account" "scanner" {
  project      = var.gcp_project_id
  account_id   = var.gcp_scanner_service_account_id
  display_name = "iam-crosscloud-pathfinder read-only scanner"
  description  = "GCPCollector's authenticating identity. Read-only IAM/Cloud Asset Inventory access only -- see this file's header comment for the exact permission-to-role mapping."
}

resource "google_project_iam_member" "scanner_cloudasset_viewer" {
  project = var.gcp_project_id
  role    = "roles/cloudasset.viewer"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_project_iam_member" "scanner_security_reviewer" {
  project = var.gcp_project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_project_iam_member" "scanner_wif_pool_viewer" {
  project = var.gcp_project_id
  role    = "roles/iam.workloadIdentityPoolViewer"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

# Impersonation access for a real human operator (or CI identity) -- NOT a
# downloaded key. Confirmed via real debugging: this binding needs a few
# minutes to propagate before impersonation actually works. If
# `gcloud auth application-default login --impersonate-service-account=...`
# fails immediately after `terraform apply`, that's IAM propagation delay,
# not a broken config -- wait a few minutes and retry rather than debugging
# the Terraform.
resource "google_service_account_iam_member" "operator_can_impersonate_scanner" {
  service_account_id = google_service_account.scanner.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "user:${var.gcp_scanner_operator_email}"
}
