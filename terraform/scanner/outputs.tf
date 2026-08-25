output "scanner_read_only_policy_arn" {
  description = "ARN of the least-privilege read-only policy -- attach to whichever IAM identity task 5 ultimately delivers the scanning credential through."
  value       = aws_iam_policy.scanner_read_only.arn
}

output "gcp_scanner_service_account_email" {
  description = "Email of GCPCollector's read-only scanning identity -- pass to --impersonate-service-account when generating ADC."
  value       = google_service_account.scanner.email
}
