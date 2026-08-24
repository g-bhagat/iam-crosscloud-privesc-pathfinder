variable "aws_region" {
  description = "AWS region (IAM is global, but the provider block still needs one)."
  type        = string
  default     = "us-east-1"
}
