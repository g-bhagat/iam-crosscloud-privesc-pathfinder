## ---------------------------------------------------------------------------
## AWS OIDC provider + role trust policy -- the CORRECTLY-SCOPED side of the
## Track 1 mismatch (task 15). This is deliberately the "control" config:
## the trust policy pins both the exact repo AND the exact branch via the
## `sub` claim, plus the standard `aud` check. The vulnerability lives
## entirely on the GCP side (gcp.tf) -- the whole point of Pattern 1
## (docs/THREAT_MODEL.md) is that a reviewer auditing *only* this AWS role
## would find nothing wrong, because there isn't anything wrong with it.
## ---------------------------------------------------------------------------

data "tls_certificate" "github_actions" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com",
  ]

  # AWS validates the TLS chain itself for this well-known issuer; the
  # thumbprint is still a required field on the resource.
  thumbprint_list = [data.tls_certificate.github_actions.certificates[0].sha1_fingerprint]

  tags = {
    Project = "iam-crosscloud-privesc-pathfinder"
    Track   = "track1"
  }
}

data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    sid     = "GitHubActionsOIDCAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # The control: pinned to one repo AND one branch, not a wildcard.
    # Compare to the GCP provider's attribute-condition in gcp.tf, which
    # is deliberately missing this level of scoping.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${var.github_branch}"]
    }
  }
}

resource "aws_iam_role" "cicd_deploy" {
  name               = var.aws_role_name
  assume_role_policy = data.aws_iam_policy_document.github_actions_trust.json

  tags = {
    Project = "iam-crosscloud-privesc-pathfinder"
    Track   = "track1"
  }
}

# --- "Moderate permission" (task 17, AWS side) ------------------------------
# A representative CI/CD deploy footprint: push build artifacts to one
# sandbox bucket, write logs. Explicitly NOT admin -- the point of Track 1
# is that the escalation happens by crossing into GCP, not by over-granting
# on the AWS side itself.

resource "random_id" "artifact_bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "deploy_artifacts" {
  bucket        = "track1-deploy-artifacts-${random_id.artifact_bucket_suffix.hex}"
  force_destroy = true # keep `terraform destroy` a clean, one-command teardown

  tags = {
    Project = "iam-crosscloud-privesc-pathfinder"
    Track   = "track1"
  }
}

resource "aws_s3_bucket_public_access_block" "deploy_artifacts" {
  bucket                  = aws_s3_bucket.deploy_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "cicd_deploy_permissions" {
  statement {
    sid    = "DeployArtifactAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.deploy_artifacts.arn,
      "${aws_s3_bucket.deploy_artifacts.arn}/*",
    ]
  }

  statement {
    sid    = "DeployLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:*:log-group:/track1/*"]
  }
}

resource "aws_iam_role_policy" "cicd_deploy_permissions" {
  name   = "track1-moderate-deploy-permissions"
  role   = aws_iam_role.cicd_deploy.id
  policy = data.aws_iam_policy_document.cicd_deploy_permissions.json
}
