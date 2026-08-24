## ---------------------------------------------------------------------------
## The AWS half of task 5: "Create a least-privilege, read-only scanning
## credential." This is the actual permission set AWSCollector authenticates
## with -- SCOPE.md rule 1's `iam:List*`/`iam:Get*` prose is the informal
## summary; this is the enumerated policy that summary stands for. Action
## list is derived directly from src/collectors/aws_collector.py's boto3
## calls, not copy-pasted from a managed policy -- if AWSCollector starts
## calling a new API, this list needs a matching line, and vice versa.
##
## Deliberately just the policy, not a role/user + trust/attachment: how the
## credential itself gets delivered (IAM user + access key, an assumable
## role, etc.) is still an open task-5 decision. Attach this policy to
## whichever identity that decision lands on.
## ---------------------------------------------------------------------------

data "aws_iam_policy_document" "scanner_read_only" {
  statement {
    sid    = "IdentityInventory"
    effect = "Allow"
    actions = [
      "iam:ListUsers",
      "iam:ListGroups",
      "iam:ListRoles",
      "iam:ListPolicies",
      "iam:ListGroupsForUser",
      "iam:ListMFADevices",
    ]
    resources = ["*"] # these are account-scoped List/Get APIs; IAM doesn't support resource-level restriction on them
  }

  statement {
    sid    = "AttachedAndInlinePolicyInspection"
    effect = "Allow"
    actions = [
      "iam:ListAttachedUserPolicies",
      "iam:ListAttachedGroupPolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListUserPolicies",
      "iam:ListGroupPolicies",
      "iam:ListRolePolicies",
      "iam:GetUserPolicy",
      "iam:GetGroupPolicy",
      "iam:GetRolePolicy",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
    ]
    resources = ["*"]
  }

  statement {
    # Added for the OIDC-provider collection stage (AWSCollector
    # _collect_oidc_providers): without these, provider-level metadata
    # (issuer URL, audience/client ID list, thumbprints) is invisible to
    # the tool, and providers no role currently trusts never surface at
    # all -- see the docstring on that method.
    sid    = "OIDCProviderInventory"
    effect = "Allow"
    actions = [
      "iam:ListOpenIDConnectProviders",
      "iam:GetOpenIDConnectProvider",
    ]
    resources = ["*"] # ListOpenIDConnectProviders takes no resource; GetOpenIDConnectProvider's ARN varies per account
  }

  statement {
    sid       = "CallerIdentity"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "scanner_read_only" {
  name        = "iam-crosscloud-pathfinder-scanner-read-only"
  description = "Least-privilege read-only policy for AWSCollector -- IAM/STS identity inventory only, no write/delete actions anywhere. See docstring in src/collectors/aws_collector.py."
  policy      = data.aws_iam_policy_document.scanner_read_only.json
}
