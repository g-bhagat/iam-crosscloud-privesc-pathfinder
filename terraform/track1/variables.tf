## ---------------------------------------------------------------------------
## Identity of the "victim" CI/CD pipeline (tasks 13-14)
## ---------------------------------------------------------------------------

variable "github_org" {
  description = "GitHub org/user that owns the victim CI/CD repo (e.g. your GitHub username)."
  type        = string
}

variable "github_repo" {
  description = "Name of the victim CI/CD repo (task 13). Does not need to exist yet unless manage_github_repo = true."
  type        = string
  default     = "iam-crosscloud-victim-pipeline"
}

variable "github_branch" {
  description = "Branch the workflow runs on -- this is the branch the AWS side (task 15) and the GCP negative control (task 18) pin to."
  type        = string
  default     = "main"
}

variable "manage_github_repo" {
  description = <<-EOT
    If true, this config also creates the victim GitHub repo and its
    Actions workflow file (tasks 13-14) via the GitHub provider -- requires
    var.github_token with repo-creation scope. If false (default), assume
    the repo + workflow already exist and this config only provisions the
    AWS/GCP trust infrastructure that workflow federates into.
  EOT
  type        = bool
  default     = false
}

variable "github_token" {
  description = "GitHub PAT with repo scope. Only required if manage_github_repo = true. Prefer the GITHUB_TOKEN env var over setting this in a .tfvars file."
  type        = string
  default     = ""
  sensitive   = true
}

## ---------------------------------------------------------------------------
## AWS side (task 15, 17 -- correctly-scoped control + moderate permission)
## ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for sandbox resources (the OIDC provider and IAM role are global, but the S3 bucket needs a region)."
  type        = string
  default     = "us-east-1"
}

variable "aws_role_name" {
  description = "Name of the AWS IAM role the GitHub Actions workflow assumes via OIDC. Correctly scoped: trust policy pins repo+branch (task 15)."
  type        = string
  default     = "track1-cicd-deploy-role"
}

## ---------------------------------------------------------------------------
## GCP side (tasks 16-18 -- the planted misconfiguration + its negative control)
## ---------------------------------------------------------------------------

variable "gcp_project_id" {
  description = "Dedicated GCP sandbox project ID (task 4). Never a production/personal project."
  type        = string
}

variable "gcp_region" {
  description = "GCP region for regional resources, if any are added later."
  type        = string
  default     = "us-central1"
}

variable "wif_pool_id" {
  description = "Workload Identity Pool ID that holds both the misconfigured provider and the negative-control provider."
  type        = string
  default     = "track1-github-pool"
}

variable "owner_service_account_id" {
  description = <<-EOT
    Service account ID (task 17) bound to the misconfigured WIF provider.
    Deliberately over-privileged (roles/owner) -- this is the blast-radius
    end of the Track 1 escalation path, not a config mistake to "fix" here.
  EOT
  type        = string
  default     = "track1-owner-sa"
}

variable "scoped_service_account_id" {
  description = "Service account ID (task 18) bound to the correctly-scoped negative-control WIF provider. Minimal privilege on purpose -- this binding must NOT be flagged by the tool."
  type        = string
  default     = "track1-scoped-sa"
}

variable "enable_gcp_apis" {
  description = "If true, enables the GCP APIs this config needs (IAM, IAM Credentials, STS, Cloud Resource Manager) on the target project. Set false if they're already enabled and your credential lacks serviceusage.services.enable."
  type        = bool
  default     = true
}
