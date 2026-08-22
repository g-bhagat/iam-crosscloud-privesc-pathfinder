output "aws_oidc_provider_arn" {
  description = "AWS IAM OIDC provider ARN (task 15)."
  value       = aws_iam_openid_connect_provider.github_actions.arn
}

output "aws_role_arn" {
  description = "ARN of the correctly-scoped AWS deploy role -- paste into the workflow's role-to-assume."
  value       = aws_iam_role.cicd_deploy.arn
}

output "aws_deploy_bucket_name" {
  description = "Sandbox S3 bucket the AWS role can read/write (the 'moderate permission' from task 17)."
  value       = aws_s3_bucket.deploy_artifacts.bucket
}

output "gcp_wif_pool_name" {
  description = "Full resource name of the shared Workload Identity Pool."
  value       = google_iam_workload_identity_pool.github.name
}

output "gcp_loose_provider_resource_name" {
  description = "Full resource name of the PLANTED-MISCONFIGURATION provider (task 16) -- this is the one the pathfinder (task 11) should be able to walk to roles/owner."
  value       = google_iam_workload_identity_pool_provider.loose.name
}

output "gcp_owner_service_account_email" {
  description = "Email of the over-privileged (roles/owner) target SA reachable via the loose provider."
  value       = google_service_account.owner_target.email
}

output "gcp_scoped_provider_resource_name" {
  description = "Full resource name of the NEGATIVE-CONTROL provider (task 18) -- correctly scoped, must not be flagged."
  value       = google_iam_workload_identity_pool_provider.scoped.name
}

output "gcp_scoped_service_account_email" {
  description = "Email of the minimally-privileged (roles/viewer) negative-control target SA."
  value       = google_service_account.scoped_target.email
}

output "github_repository_html_url" {
  description = "URL of the managed victim repo, if manage_github_repo = true."
  value       = var.manage_github_repo ? github_repository.victim_pipeline[0].html_url : null
}
