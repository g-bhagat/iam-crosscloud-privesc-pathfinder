# Track 2 Terraform — overly-broad GCP WIF trust of an AWS principal

> **This config encodes infrastructure that has already been manually
> built, debugged, and validated live** — a real AWS→GCP token exchange
> succeeded against this exact shape, and the tool's actual detection
> pipeline (collectors → correlation → escalation rules) fired a real
> Finding against it. This is formalization into Terraform, not
> first-time design; every gotcha documented below was hit for real
> during that validation, not anticipated in the abstract.

Provisions the sandbox infrastructure for `TASKS.md` tasks 24–30: a GCP
Workload Identity Pool with two AWS-type providers trusting the sandbox
AWS account directly — no third-party OIDC issuer anywhere in this
track, unlike Track 1. One provider is deliberately scoped only to the
AWS account (the planted misconfiguration); the other pins a specific
AWS role (the negative control). Full rationale in
[`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md) — Pattern 2.

## What this creates

| Resource | File | Notes |
|---|---|---|
| Minimal AWS role, assumable by the sandbox account itself | `aws.tf` | Not the vulnerability — just a real, testable AWS session for the PoC |
| GCP WIF pool + AWS-type provider scoped only to the AWS account ID | `gcp.tf` | **Planted misconfiguration** |
| GCP SA with `roles/owner`, bound to the account-only provider | `gcp.tf` | The blast radius |
| GCP WIF AWS-type provider pinned to one specific assumed-role ARN | `gcp.tf` | **Negative control** |
| GCP SA with `roles/viewer`, bound to the role-scoped provider | `gcp.tf` | Must NOT be flagged |

## The misconfiguration, precisely

Both GCP WIF providers here are **AWS-type** (`aws { account_id = ... }`),
not OIDC-type — GCP trusting the AWS account's own STS-issued identity
assertions directly, no external OIDC issuer bridging the two clouds at
all. That's what makes this structurally different from Track 1.

The "scoped" provider's `attribute_condition` pins one specific role via
`assertion.arn.startsWith('arn:aws:sts::<account>:assumed-role/track2-test-role/')`
— only sessions assumed as `track2-test-role` can use it. The "loose"
provider has **no `attribute_condition` at all**. The provider-level
`account_id` restriction is real narrowing (only this one AWS account
can reach it) — but it's account-*wide*: any IAM principal in that
account that can sign a valid AWS request can obtain a token for this
provider, not just `track2-test-role`. That's the whole gap: one missing
`attribute_condition` line is the difference between "one specific role"
and "anyone with credentials in this account."

## GCP AWS-type provider gotchas (confirmed through real debugging)

These are not obvious from GCP's docs alone — each one was hit for real
building this infrastructure the first time.

- **No default `attribute.account` mapping.** GCP's AWS-type provider
  only applies `google.subject = assertion.arn` by default, and
  specifying *any* custom `attribute_mapping` replaces the default
  rather than extending it. Both `google.subject` and
  `attribute.account` must be listed explicitly, or the loose binding
  below has no `attribute.account` path to match against at all.
- **The loose binding's member path is `attribute.account`, not
  `attribute.aws_account`.** That attribute doesn't exist on this
  provider's mapping — get the name wrong and the binding silently
  matches nothing, ever, with no error at apply time or at token-exchange
  time. It just quietly never grants anything.
- **The scoped binding needs the FULL ARN, session name included.**
  `google.subject`'s default mapping is the *complete* `assertion.arn`
  — for an assumed-role session that includes the dynamic session-name
  suffix (`arn:aws:sts::<account>:assumed-role/<role>/<session-name>`).
  A `principal://` binding (unlike `principalSet://`) matches exactly
  one literal subject string, so this only works because
  `var.aws_session_name` is fixed and the PoC always assumes
  `track2-test-role` with that exact `--role-session-name`. This is a
  *tighter*, more specific match than the provider-level
  `attribute_condition`, which only needs to stop at the role name.
- **Stop the `attribute_condition` prefix exactly at the role name.**
  `confidence.py`'s `score_gcp_condition()` recognizes a role-level pin
  via the regex `assumed-role/[^/]+/?$` — a prefix that includes a
  session-name segment (or anything past the role name) won't match it,
  and the edge scores MEDIUM instead of HIGH.
- **WIF providers soft-delete.** Recreating a provider with the same ID
  immediately after deleting it fails with `ALREADY_EXISTS`; `update`
  on it during that same window can fail with `NOT_FOUND`. Use
  `terraform destroy` / `terraform apply` as a full cycle — never
  manually delete-then-recreate a provider outside Terraform while
  iterating, or you'll hit both errors depending on which command you
  reach for.

## Prerequisites

- Terraform >= 1.5
- A dedicated AWS sandbox account (task 3) with credentials able to
  create an IAM role — **not** the read-only scanning credential from
  task 5, which can't create anything.
- A dedicated GCP sandbox project (task 4) with credentials able to
  create service accounts, WIF pools/providers, and IAM bindings.
- `gcloud` and `aws` CLIs installed locally for the PoC section below
  (not required just to `terraform apply`).

Credentials: standard provider resolution applies — `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` (or an AWS profile) for the `aws` provider,
`GOOGLE_APPLICATION_CREDENTIALS` for the `google` provider. Per
`SCOPE.md`, these must be sandbox-account credentials — never point this
at a production/personal account or project.

## Usage

```bash
cd terraform/track2
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your sandbox gcp_project_id / etc.

terraform init
terraform plan   # review before applying -- confirm no real prod resources targeted
terraform apply
```

## Validating the real token exchange (PoC)

This is the actual live-tested procedure, not a theoretical description
— every step below was hit for real, including the failure modes called
out.

**1. Assume `track2-test-role` and capture a real AWS session.** Use the
session name Terraform is configured with (`var.aws_session_name`,
default `track2-poc-session`) — the scoped negative-control binding is
pinned to it (see the gotchas above), so a different session name won't
match it.

```bash
ROLE_ARN=$(terraform output -raw aws_test_role_arn)
SESSION_NAME=track2-poc-session   # must match var.aws_session_name

aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name "$SESSION_NAME" \
  --output json > /tmp/track2-creds.json
```

Use `--output json`, **not** `--output text` — the text format is
tab-delimited and naive space-splitting of it silently corrupts
credential parsing (a session token in particular is long enough to
contain characters that break a careless split). Parse the JSON
properly instead:

```bash
export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' /tmp/track2-creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' /tmp/track2-creds.json)
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' /tmp/track2-creds.json)
export AWS_REGION=us-east-1   # match var.aws_region -- see note below
```

**2. Generate a GCP credential config from those AWS credentials.**

```bash
PROVIDER_NAME=$(terraform output -raw gcp_loose_provider_resource_name)   # or gcp_scoped_provider_resource_name
TARGET_SA=$(terraform output -raw gcp_owner_service_account_email)        # or gcp_scoped_service_account_email

gcloud iam workload-identity-pools create-cred-config \
  "$PROVIDER_NAME" \
  --service-account="$TARGET_SA" \
  --aws \
  --output-file=/tmp/track2-cred-config.json
```

`AWS_REGION` **must** be set explicitly in the environment before this
command — `create-cred-config --aws` queries EC2 instance metadata by
default to determine the region, and that query fails outright when
you're not running on an EC2 instance (i.e. from a laptop, which is the
normal case for this PoC).

**3. Exchange for a real Google access token.**

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/tmp/track2-cred-config.json
gcloud auth application-default print-access-token
```

A token printed here is the actual proof: AWS credentials from
`track2-test-role` were exchanged for a Google-federated token
impersonating the target SA. Run this against the loose provider's
owner-privileged SA to confirm the true positive; run it against the
scoped provider's viewer SA (with a session that does *not* match
`var.aws_session_name`) to confirm the negative control correctly
rejects the exchange.

## Validating true positive / true negative (tasks 27–28)

- The loose provider → `owner_target` SA path should surface as a
  **MEDIUM-confidence** `FEDERATES_WITH` edge (real federation, but
  scoped to an entire AWS account rather than one role — see
  `docs/THREAT_MODEL.md` §4) terminating at an `is_admin=True` node —
  the true positive, flagged by `escalation_rules.py`'s pattern 2 check.
- The scoped provider → `scoped_target` SA path should score **HIGH**
  confidence and produce **no** escalation finding — the true negative.
  If the rule engine ever flags it, that's a bug in the rule engine, not
  a problem with this Terraform.

## Cost / safety

Everything here is IAM/WIF-only — no compute, no storage, no networking.
Zero cost at this scale on either cloud. `track2-test-role` grants no
AWS permissions beyond being assumable; what matters for the PoC is the
session it produces, not anything it can do in AWS.

## Teardown

```bash
terraform destroy
```

Do a full `destroy`/`apply` cycle if you need to recreate providers —
see the soft-delete gotcha above. Never manually delete a WIF provider
outside Terraform while other resources in this config still reference
it.

## State handling

Local backend, on purpose (solo sandbox project, no team to share state
with). `terraform.tfstate` will contain your real AWS account ID and GCP
project ID once you apply — it is covered by the repo-root `.gitignore`.
Never commit it, never paste its contents into a public issue/PR, and
sanitize before any screenshot of `terraform output` goes into `docs/`
(SCOPE.md rule 5).
