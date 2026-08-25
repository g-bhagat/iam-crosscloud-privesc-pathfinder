# Track 3 Terraform — mirror-direction AWS-trusts-GCP escalation

> **This config encodes infrastructure that has already been manually
> built, debugged, and validated live** — a real GCP→AWS token exchange
> succeeded against this exact shape (`AssumeRoleWithWebIdentity` using a
> Google-issued identity token), and the tool's actual detection
> pipeline (collectors → correlation → escalation rules) fired a real
> Finding against it. This is formalization into Terraform, not
> first-time design; every gotcha documented below — the built-in
> provider trap, the `oaud`/`aud` naming swap, the token-file trailing
> newline — was hit for real during that validation, not anticipated in
> the abstract.

Provisions the sandbox infrastructure for `TASKS.md` tasks 35–43: an AWS
IAM role whose trust policy accepts `AssumeRoleWithWebIdentity` calls
validated against Google's own OIDC issuer (`accounts.google.com`) —
AWS's outbound identity federation, the reverse of Track 2's mechanism.
See [`SCOPE.md`](../../SCOPE.md) "Reversed decisions" for why this track
exists and what it is (and is not) structurally necessary for. Full
rationale in [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md) —
Pattern 3.

## What this creates

| Resource | File | Notes |
|---|---|---|
| AWS role trusting `accounts.google.com`, `sub` unpinned, `AdministratorAccess` | `aws.tf` | **Planted misconfiguration** — the `is_admin` target |
| AWS role trusting `accounts.google.com`, `sub` pinned to one GCP SA, `ReadOnlyAccess` | `aws.tf` | **Negative control** — must NOT be flagged |
| GCP service account with no notable GCP permissions of its own | `gcp.tf` | Looks unremarkable from GCP's own perspective — the whole point |
| Grant letting the operator impersonate that SA (for the PoC) | `gcp.tf` | So token generation works without a manual extra step |

## The misconfiguration, precisely

Both AWS roles trust the bare Federated principal `accounts.google.com`
and both check `accounts.google.com:oaud == "sts.amazonaws.com"` (the
audience check — see the naming gotcha below). The scoped role
*additionally* checks `accounts.google.com:sub`, pinned to
`track3_ordinary`'s specific numeric Google ID — only an identity token
generated *by that one SA* can assume it. The loose role has no `sub`
condition at all: any Google-issued identity token audienced to
`sts.amazonaws.com`, from *any* GCP principal that can generate one, can
assume it — and it carries `AdministratorAccess`.

Track 3's framing (see `SCOPE.md`) is deliberately modest: this is *not*
the structurally cross-cloud-necessary pattern (an AWS-only tool can
determine `track3_loose`'s `is_admin` status and read its own trust
condition using only AWS-native data — same limitation Track 1's GCP-side
check has, just mirrored). Its value is that it's a distinct,
less-commonly-audited misconfiguration class — AWS's newer *outbound*
identity federation feature — and it completes the secure/insecure test
matrix across both trust directions instead of testing only one.

## CRITICAL: do not create an OIDC provider resource for Google

Confirmed through extensive real debugging, and worth repeating outside
`aws.tf`'s own comments because it's the single easiest way to burn an
afternoon on this track: **Google is one of AWS's built-in web identity
providers** (alongside Amazon Cognito, Login with Amazon, and Facebook —
see AWS's own `AssumeRoleWithWebIdentity` docs). Creating an
`aws_iam_openid_connect_provider` resource for `accounts.google.com` is
the *wrong mechanism entirely*. It registers a generic OIDC provider
resource, which is not how AWS validates tokens from one of its
natively-recognized built-in providers — and it produces
`InvalidIdentityToken` at `AssumeRoleWithWebIdentity` time, regardless of
how correctly everything else is configured. The trust policy's
`Federated` principal must be the bare string `"accounts.google.com"`,
never an ARN.

## The `oaud` / `aud` naming gotcha (confirmed through real debugging)

AWS's condition key `accounts.google.com:aud` actually checks the
token's `azp` (authorized party) claim, **not** its `aud` claim.
`accounts.google.com:oaud` is the one that checks the real `aud`. This
is backwards from what the names suggest, it is not documented
prominently, and getting it wrong doesn't error at apply time or even at
`AssumeRoleWithWebIdentity` time in an obviously-diagnosable way — the
condition just silently never matches what you intended, and the
assumption fails with no hint that the *condition key itself*, not the
token or the role, is the actual problem.

## Prerequisites

- Terraform >= 1.5
- A dedicated AWS sandbox account (task 3) with credentials able to
  create IAM roles and attach managed policies — **not** the read-only
  scanning credential from task 5.
- A dedicated GCP sandbox project (task 4) with credentials able to
  create service accounts and IAM bindings.
- `gcloud` and `aws` CLIs installed locally for the PoC section below.

Credentials: standard provider resolution applies —
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (or an AWS profile) for the
`aws` provider, `GOOGLE_APPLICATION_CREDENTIALS` for the `google`
provider. `gcp.tf`'s `data.google_client_openid_userinfo` data source
needs the applying identity's own email visible in its credentials
(true by default for `gcloud auth application-default login`). Per
`SCOPE.md`, these must be sandbox-account credentials — never point this
at a production/personal account or project.

## Usage

```bash
cd terraform/track3
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your sandbox gcp_project_id / etc.

terraform init
terraform plan   # review before applying -- confirm no real prod resources targeted
terraform apply
```

If you're applying as a GCP service account rather than a human user,
edit the `member = "user:..."` line in `gcp.tf`'s
`operator_can_impersonate` resource to `"serviceAccount:..."` first.

## Validating the real token exchange (PoC)

This is the actual live-tested procedure — every step, including the
failure mode called out, was hit for real.

**1. Generate a Google identity token, impersonating the ordinary SA.**

```bash
SA_EMAIL=$(terraform output -raw gcp_ordinary_service_account_email)

gcloud auth print-identity-token \
  --impersonate-service-account="$SA_EMAIL" \
  --audiences=sts.amazonaws.com > /tmp/track3-google-token.txt
```

**2. Exchange it for real AWS credentials.**

```bash
ROLE_ARN=$(terraform output -raw aws_loose_role_arn)   # or aws_scoped_role_arn

aws sts assume-role-with-web-identity \
  --role-arn "$ROLE_ARN" \
  --role-session-name track3-poc-session \
  --web-identity-token "$(cat /tmp/track3-google-token.txt)"
```

Pass the token via `"$(cat /tmp/track3-google-token.txt)"`, **not**
`--web-identity-token file:///tmp/track3-google-token.txt`. The `file://`
form can retain a trailing newline from how the token was written to
disk, and that trailing newline breaks the request's signature
validation — the call fails with an error that doesn't point at "your
token has a stray newline" as the cause. Reading the file into the
argument directly avoids the issue entirely.

Run this against `aws_loose_role_arn` to confirm the true positive
(succeeds, returns `AdministratorAccess`-scoped credentials). Run it
against `aws_scoped_role_arn` using an identity token generated for a
*different* GCP principal to confirm the negative control correctly
rejects the exchange.

## Validating true positive / true negative (task 41)

- `track3_loose`'s trust condition should score **MEDIUM** confidence
  (real federation present, but the subject isn't pinned to one specific
  principal — see `docs/THREAT_MODEL.md` §4) and, since it carries
  `AdministratorAccess` (`is_admin=True`), surface as a **pattern 3**
  Finding via `escalation_rules.py` — the true positive.
- `track3_scoped`'s trust condition (subject pinned via
  `accounts.google.com:sub`) should score **HIGH** confidence and
  produce **no** escalation finding — the true negative. If the rule
  engine ever flags it, that's a bug in the rule engine, not a problem
  with this Terraform.

## Cost / safety

Everything here is IAM/WIF-only — no compute, no storage, no networking.
Zero cost at this scale on either cloud. `track3_ordinary` is granted no
notable GCP permissions; the operator-impersonation grant only lets
*you* generate tokens as it for the PoC, it doesn't broaden what the SA
itself can do.

## Teardown

```bash
terraform destroy
```

## State handling

Local backend, on purpose (solo sandbox project, no team to share state
with). `terraform.tfstate` will contain your real AWS account ID and GCP
project ID once you apply — it is covered by the repo-root `.gitignore`.
Never commit it, never paste its contents into a public issue/PR, and
sanitize before any screenshot of `terraform output` goes into `docs/`
(SCOPE.md rule 5).
