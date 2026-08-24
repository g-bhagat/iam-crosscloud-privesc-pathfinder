terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Local backend, gitignored state -- same rationale as terraform/track1.
}

provider "aws" {
  region = var.aws_region
}
