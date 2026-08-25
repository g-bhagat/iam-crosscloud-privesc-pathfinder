## ---------------------------------------------------------------------------
## AWS side -- the planted misconfiguration (unpinned Google subject) and its
## negative control (pinned to one specific GCP SA).
## ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for the aws provider. Both IAM roles are global resources, but the provider still needs a region."
  type        = string
  default     = "us-east-1"
}

variable "aws_loose_role_name" {
  description = <<-EOT
    Name of the AWS role with the planted misconfiguration: trusts
    Google's built-in issuer (accounts.google.com) but never pins a
    specific GCP principal via the accounts.google.com:sub condition.
    AdministratorAccess attached -- this is the is_admin target of the
    Track 3 escalation.
  EOT
  type        = string
  default     = "track3-loose-role"
}

variable "aws_scoped_role_name" {
  description = "Name of the AWS role that additionally pins accounts.google.com:sub to track3-ordinary-sa's specific numeric ID. ReadOnlyAccess attached -- negative control, must not be flagged."
  type        = string
  default     = "track3-scoped-role"
}

## ---------------------------------------------------------------------------
## GCP side -- the ordinary-looking SA that's the real actor in this
## escalation. It has no notable GCP permissions of its own; the whole
## escalation path exists on the AWS side (aws.tf).
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

variable "ordinary_service_account_id" {
  description = "Service account ID for the GCP SA that looks unremarkable from GCP's own perspective -- no notable GCP permissions of its own. Its escalation path exists entirely on the AWS side (aws.tf)."
  type        = string
  default     = "track3-ordinary-sa"
}

variable "enable_gcp_apis" {
  description = "If true, enables the GCP APIs this config needs (IAM, IAM Credentials, Cloud Resource Manager) on the target project. Set false if they're already enabled and your credential lacks serviceusage.services.enable."
  type        = bool
  default     = true
}
