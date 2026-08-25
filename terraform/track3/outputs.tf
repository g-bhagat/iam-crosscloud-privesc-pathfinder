output "aws_loose_role_arn" {
  description = "ARN of the PLANTED-MISCONFIGURATION AWS role (AdministratorAccess, unpinned Google subject) -- the escalation target."
  value       = aws_iam_role.track3_loose.arn
}

output "aws_scoped_role_arn" {
  description = "ARN of the NEGATIVE-CONTROL AWS role (ReadOnlyAccess, subject pinned to track3-ordinary-sa). Must not be flagged."
  value       = aws_iam_role.track3_scoped.arn
}

output "gcp_ordinary_service_account_email" {
  description = "Email of the ordinary-looking GCP SA whose identity tokens can assume the loose AWS role."
  value       = google_service_account.track3_ordinary.email
}

output "gcp_ordinary_service_account_unique_id" {
  description = "Google's stable numeric ID for the ordinary SA -- this is the value accounts.google.com:sub carries in its tokens, and what the scoped role's trust condition pins to."
  value       = google_service_account.track3_ordinary.unique_id
}
