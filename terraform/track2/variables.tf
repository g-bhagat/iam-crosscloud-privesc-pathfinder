## ---------------------------------------------------------------------------
## AWS side -- a real, minimal, testable AWS identity, not itself the
## vulnerability. It exists purely so there's a real AWS session to exchange
## for a GCP token during the PoC (README.md).
## ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for the aws provider. The IAM role itself is global, but the provider still needs a region, and gcloud's create-cred-config queries this too (see README.md)."
  type        = string
  default     = "us-east-1"
}

variable "aws_test_role_name" {
  description = "Name of the minimal AWS IAM role used to generate a real, testable AWS session for the Track 2 PoC token exchange. Trust policy allows the sandbox account's own root principal to assume it."
  type        = string
  default     = "track2-test-role"
}

variable "aws_session_name" {
  description = <<-EOT
    Fixed --role-session-name used every time track2-test-role is
    assumed for the PoC. The scoped (negative-control) WIF provider's
    IAM binding pins a literal principal:// subject that includes this
    session name -- google.subject's default mapping on an AWS-type
    provider is the FULL assertion.arn, session name included, so the
    binding only matches when the session name matches too. Always pass
    --role-session-name <this value> to `aws sts assume-role`.
  EOT
  type        = string
  default     = "track2-poc-session"
}

## ---------------------------------------------------------------------------
## GCP side -- the planted misconfiguration (account-only-scoped AWS-type WIF
## provider) and its negative control (role-scoped).
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
  description = "Workload Identity Pool ID that holds both the account-only-scoped provider and its role-scoped negative control."
  type        = string
  default     = "track2-aws-direct-pool"
}

variable "owner_service_account_id" {
  description = <<-EOT
    Service account ID bound to the account-only-scoped WIF provider.
    Deliberately over-privileged (roles/owner) -- this is the
    blast-radius end of the Track 2 escalation path, not a config
    mistake to "fix" here.
  EOT
  type        = string
  default     = "track2-owner-sa"
}

variable "scoped_service_account_id" {
  description = "Service account ID bound to the correctly-scoped negative-control WIF provider. Minimal privilege on purpose -- this binding must NOT be flagged by the tool."
  type        = string
  default     = "track2-scoped-sa"
}

variable "enable_gcp_apis" {
  description = "If true, enables the GCP APIs this config needs (IAM, IAM Credentials, STS, Cloud Resource Manager) on the target project. Set false if they're already enabled and your credential lacks serviceusage.services.enable."
  type        = bool
  default     = true
}
