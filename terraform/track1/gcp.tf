## ---------------------------------------------------------------------------
## GCP Workload Identity Federation -- this file is where Pattern 1's actual
## vulnerability lives (docs/THREAT_MODEL.md). One pool, two providers:
##
##   - "loose"  (task 16): attribute-condition checks only the GitHub ORG,
##     not the specific repo or branch. Bound (task 17) to a service account
##     with roles/owner. ANY repo in the org can mint a token that
##     impersonates it -- this is the planted misconfiguration.
##   - "scoped" (task 18): attribute-condition pins the exact repo AND ref,
##     mirroring the AWS-side control in aws.tf. Bound to a minimally
##     privileged service account. This is the negative control: the tool
##     must NOT flag this binding as an escalation path.
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

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = var.wif_pool_id
  display_name              = "Track 1 GitHub Actions pool"
  description               = "Holds the Track 1 misconfigured + negative-control WIF providers. See docs/THREAT_MODEL.md Pattern 1."

  depends_on = [google_project_service.required]
}

# --- The planted misconfiguration (task 16) ---------------------------------

resource "google_iam_workload_identity_pool_provider" "loose" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "gh-loose-org-scope"
  display_name                       = "Loosely-scoped GitHub OIDC (PLANTED MISCONFIG)"
  description                        = "attribute-condition checks repository_owner only -- any repo in the org can assume the bound owner-privileged SA. Do not copy this pattern."

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
  }

  # THE VULNERABILITY: scoped to the GitHub org, not the specific repo or
  # branch. Compare to the "scoped" provider below and to the AWS trust
  # policy's `sub` condition in aws.tf, which pins repo+branch.
  attribute_condition = "assertion.repository_owner == \"${var.github_org}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "owner_target" {
  account_id   = var.owner_service_account_id
  display_name = "Track 1 target SA (roles/owner) -- reachable via the loose WIF provider"
}

resource "google_project_iam_member" "owner_target_is_owner" {
  project = var.gcp_project_id
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.owner_target.email}"
}

# Grants the *entire org-scoped principal set* from the loose provider the
# ability to impersonate the owner-privileged SA. This single binding is
# the escalation path: any workflow in var.github_org, not just
# var.github_repo, can now mint tokens that act as GCP project owner.
resource "google_service_account_iam_member" "loose_binding" {
  service_account_id = google_service_account.owner_target.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository_owner/${var.github_org}"
}

# --- The negative control (task 18) -----------------------------------------

resource "google_iam_workload_identity_pool_provider" "scoped" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "gh-scoped-repo-branch"
  display_name                       = "Correctly-scoped GitHub OIDC (negative control)"
  description                        = "attribute-condition pins the exact repo AND ref. Must NOT be flagged by the escalation rule engine."

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  # The control: exact repo AND exact branch, mirroring the AWS side.
  attribute_condition = "assertion.repository == \"${var.github_org}/${var.github_repo}\" && assertion.ref == \"refs/heads/${var.github_branch}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "scoped_target" {
  account_id   = var.scoped_service_account_id
  display_name = "Track 1 negative-control target SA (minimal privilege)"
}

# Deliberately minimal: read-only viewer, nowhere near roles/owner. Paired
# with the tight attribute-condition above, this binding is the "prove a
# true negative" half of the Track 1 validation (SCOPE.md success criteria).
resource "google_project_iam_member" "scoped_target_is_viewer" {
  project = var.gcp_project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.scoped_target.email}"
}

resource "google_service_account_iam_member" "scoped_binding" {
  service_account_id = google_service_account.scoped_target.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}
