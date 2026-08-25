## ---------------------------------------------------------------------------
## AWS side -- deliberately minimal. track2-test-role is NOT the
## vulnerability; Track 2's whole point (docs/THREAT_MODEL.md Pattern 2) is
## that the escalation happens entirely on the GCP side (gcp.tf), by trusting
## an AWS account too broadly. This role exists only so there's a real,
## testable AWS session to exchange for a GCP token during the PoC.
## ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "test_role_trust" {
  statement {
    sid     = "AllowOwnAccountAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "test_role" {
  name               = var.aws_test_role_name
  assume_role_policy = data.aws_iam_policy_document.test_role_trust.json

  tags = {
    Project = "iam-crosscloud-privesc-pathfinder"
    Track   = "track2"
  }
}

# No permissions attached beyond the ability to be assumed -- what this role
# can do *in AWS* is irrelevant to Track 2's mechanism. What matters is that
# assuming it produces a real AWS session whose SigV4-signed request GCP's
# AWS-type WIF provider will accept as proof of "a principal in this AWS
# account," per gcp.tf's account-id scoping.
