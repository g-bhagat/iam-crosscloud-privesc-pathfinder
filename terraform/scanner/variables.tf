variable "aws_region" {
  description = "AWS region (IAM is global, but the provider block still needs one)."
  type        = string
  default     = "us-east-1"
}

## ---------------------------------------------------------------------------
## GCP half of task 5 (gcp.tf)
## ---------------------------------------------------------------------------

variable "gcp_project_id" {
  description = "Dedicated GCP sandbox project ID (task 4). Never a production/personal project."
  type        = string
}

variable "gcp_region" {
  description = "GCP region for the provider block. No resource in this module is regional, but every other module in this repo declares one for consistency."
  type        = string
  default     = "us-central1"
}

variable "gcp_scanner_service_account_id" {
  description = "Service account ID for GCPCollector's read-only scanning identity."
  type        = string
  default     = "iam-pathfinder-scanner"
}

variable "gcp_scanner_operator_email" {
  description = <<-EOT
    Email of the human GCP account (or CI identity) that will impersonate
    the scanner service account to run GCPCollector -- e.g. via
    `gcloud auth application-default login
    --impersonate-service-account=...`. Granted roles/iam.serviceAccountTokenCreator
    on the scanner SA (gcp.tf); no default, since this is inherently
    specific to whoever's running the tool.
  EOT
  type        = string
}
