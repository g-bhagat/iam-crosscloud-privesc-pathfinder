terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Local backend deliberately, for a solo sandbox project. terraform.tfstate
  # contains real account IDs / project IDs / resource ARNs once applied --
  # it is gitignored (see repo root .gitignore) and must never be committed,
  # per SCOPE.md rule 5.
}

provider "aws" {
  region = var.aws_region
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Only authenticates / does anything if manage_github_repo = true and a
# github_* resource actually gets created (count-gated in github.tf) --
# safe to declare unconditionally.
provider "github" {
  owner = var.github_org
  token = var.github_token
}
