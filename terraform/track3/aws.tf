## ---------------------------------------------------------------------------
## AWS side of Track 3 (docs/THREAT_MODEL.md Pattern 3) -- this is where the
## actual vulnerability lives: AWS's outbound identity federation trusting
## Google's issuer too broadly.
##
## CRITICAL, confirmed through extensive real debugging: Google is one of
## AWS's built-in web identity providers (alongside Amazon Cognito, Login
## with Amazon, and Facebook) -- see AWS's own AssumeRoleWithWebIdentity
## docs. Do NOT create an aws_iam_openid_connect_provider resource for
## accounts.google.com. That's the wrong mechanism entirely: it registers a
## generic OIDC provider resource, which is NOT how AWS validates tokens
## from one of its natively-recognized providers, and produces
## InvalidIdentityToken at AssumeRoleWithWebIdentity time regardless of how
## correctly everything else here is configured. The trust policy's
## Federated principal must be the bare string "accounts.google.com", not an
## ARN referencing a provider resource -- there is no provider resource,
## and there should not be one.
## ---------------------------------------------------------------------------

# --- The planted misconfiguration --------------------------------------------

data "aws_iam_policy_document" "track3_loose_trust" {
  statement {
    sid     = "GoogleWebIdentityAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["accounts.google.com"]
    }

    # THE VULNERABILITY: only checks the audience, never pins WHICH GCP
    # principal's token is acceptable (that's accounts.google.com:sub,
    # only present on the scoped role below). Any Google-issued identity
    # token audienced to sts.amazonaws.com -- from ANY GCP service
    # account or user that can generate one -- can assume this role.
    #
    # NAMING GOTCHA, confirmed through real debugging: AWS's condition
    # key "accounts.google.com:aud" actually checks the token's `azp`
    # claim, NOT its `aud` claim. "accounts.google.com:oaud" is the one
    # that checks the real `aud`. Get this backwards (as it's easy to,
    # since "aud" is the obviously-named one) and the condition silently
    # never matches what you think it does -- AssumeRoleWithWebIdentity
    # just fails, with no indication the condition key itself was wrong.
    condition {
      test     = "StringEquals"
      variable = "accounts.google.com:oaud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "track3_loose" {
  name               = var.aws_loose_role_name
  assume_role_policy = data.aws_iam_policy_document.track3_loose_trust.json

  tags = {
    Project = "iam-crosscloud-privesc-pathfinder"
    Track   = "track3"
  }
}

resource "aws_iam_role_policy_attachment" "track3_loose_admin" {
  role       = aws_iam_role.track3_loose.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# --- The negative control -----------------------------------------------------

data "aws_iam_policy_document" "track3_scoped_trust" {
  statement {
    sid     = "GoogleWebIdentityAssumeScoped"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["accounts.google.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "accounts.google.com:oaud"
      values   = ["sts.amazonaws.com"]
    }

    # The control: ALSO pins the token's subject via
    # accounts.google.com:sub, to Google's stable numeric ID for
    # track3_ordinary specifically -- the same value that ID's own
    # generated tokens carry as `sub`. Only that one specific GCP SA's
    # token can assume this role.
    condition {
      test     = "StringEquals"
      variable = "accounts.google.com:sub"
      values   = [google_service_account.track3_ordinary.unique_id]
    }
  }
}

resource "aws_iam_role" "track3_scoped" {
  name               = var.aws_scoped_role_name
  assume_role_policy = data.aws_iam_policy_document.track3_scoped_trust.json

  tags = {
    Project = "iam-crosscloud-privesc-pathfinder"
    Track   = "track3"
  }
}

resource "aws_iam_role_policy_attachment" "track3_scoped_readonly" {
  role       = aws_iam_role.track3_scoped.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
