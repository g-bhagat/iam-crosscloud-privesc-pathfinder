output "aws_test_role_arn" {
  description = "ARN of the minimal AWS role used to generate a testable AWS session for the PoC token exchange."
  value       = aws_iam_role.test_role.arn
}

output "aws_account_id" {
  description = "AWS sandbox account ID -- referenced by both GCP WIF providers' account-id/attribute_condition scoping."
  value       = data.aws_caller_identity.current.account_id
}

output "gcp_wif_pool_name" {
  description = "Full resource name of the shared AWS-direct Workload Identity Pool."
  value       = google_iam_workload_identity_pool.aws_direct.name
}

output "gcp_loose_provider_resource_name" {
  description = "Full resource name of the PLANTED-MISCONFIGURATION provider (account-only scoped) -- this is the one the pathfinder should be able to walk to roles/owner."
  value       = google_iam_workload_identity_pool_provider.loose.name
}

output "gcp_owner_service_account_email" {
  description = "Email of the over-privileged (roles/owner) target SA reachable via the loose provider."
  value       = google_service_account.owner_target.email
}

output "gcp_scoped_provider_resource_name" {
  description = "Full resource name of the NEGATIVE-CONTROL provider (role-scoped) -- correctly scoped, must not be flagged."
  value       = google_iam_workload_identity_pool_provider.scoped.name
}

output "gcp_scoped_service_account_email" {
  description = "Email of the minimally-privileged (roles/viewer) negative-control target SA."
  value       = google_service_account.scoped_target.email
}
