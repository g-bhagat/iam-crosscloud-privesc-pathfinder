output "scanner_read_only_policy_arn" {
  description = "ARN of the least-privilege read-only policy -- attach to whichever IAM identity task 5 ultimately delivers the scanning credential through."
  value       = aws_iam_policy.scanner_read_only.arn
}
