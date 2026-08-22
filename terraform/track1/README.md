# Track 1 Terraform — CI/CD OIDC trust mismatch

Provisions the sandbox infrastructure for `TASKS.md` tasks 13–18: a
"victim" GitHub Actions CI/CD pipeline that federates into both AWS and
GCP, where the AWS side is correctly scoped and the GCP side carries a
deliberately planted, loosely-scoped Workload Identity Federation trust —
plus a correctly-scoped negative control. Full rationale in
[`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md) — Pattern 1.

## What this creates

| Resource | File | Task | Notes |
|---|---|---|---|
| GitHub repo + Actions workflow (`id-token: write`) | `github.tf` | 13–14 | Optional, gated by `manage_github_repo` |
| AWS OIDC provider + IAM role, trust pinned to repo+branch | `aws.tf` | 15 | **Control** — correctly scoped |
| AWS role's "moderate" deploy permissions (S3 + CloudWatch Logs) | `aws.tf` | 17 (AWS half) | Explicitly not admin |
| GCP WIF pool + provider scoped only to the GitHub org | `gcp.tf` | 16 | **Planted misconfiguration** |
| GCP SA with `roles/owner`, bound to the loose provider | `gcp.tf` | 17 (GCP half) | The blast radius |
| GCP WIF provider pinned to exact repo+branch | `gcp.tf` | 18 | **Negative control** |
| GCP SA with `roles/viewer`, bound to the scoped provider | `gcp.tf` | 18 | Must NOT be flagged |

## The misconfiguration, precisely

Both the AWS role's trust policy and the GCP "scoped" provider's
`attribute_condition` pin **both** the exact repo and the exact branch. The
GCP "loose" provider's `attribute_condition` checks **only**
`assertion.repository_owner` — i.e. it accepts a token from *any* repo
under `var.github_org`, not just `var.github_repo`. That's the whole gap:
one line (`attribute_condition = "assertion.repository_owner == ..."` vs.
`"assertion.repository == ... && assertion.ref == ..."`) is the difference
between a scoped trust and an org-wide one bound to a project-owner
service account.

## Prerequisites

- Terraform >= 1.5
- A dedicated AWS sandbox account (task 3) with credentials able to create
  IAM OIDC providers/roles and an S3 bucket — **not** the read-only
  scanning credential from task 5, which can't create anything.
- A dedicated GCP sandbox project (task 4) with credentials able to create
  service accounts, IAM bindings, and (if `enable_gcp_apis = true`) enable
  APIs — again, not the task 5 read-only credential.
- If `manage_github_repo = true`: a GitHub PAT with `repo` scope in
  `GITHUB_TOKEN`.

Credentials: standard provider resolution applies — `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` (or an AWS profile) for the `aws` provider,
`GOOGLE_APPLICATION_CREDENTIALS` for the `google` provider. Nothing here
reads or writes credentials directly; Terraform's own provider auth
handles it. Per `SCOPE.md`, these must be sandbox-account credentials —
never point this at a production/personal account or project.

## Usage

```bash
cd terraform/track1
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your sandbox github_org / gcp_project_id / etc.

terraform init
terraform plan   # review before applying -- confirm no real prod resources targeted
terraform apply
```

After apply, `terraform output` gives you the AWS role ARN and GCP
provider/SA resource names to wire into the workflow (`github.tf`'s
generated workflow has `PLACEHOLDER` markers for the GCP values if you
didn't set `manage_github_repo = true`).

## Validating true positive / true negative (task 19–20)

Once collectors (tasks 7–8), the correlation engine (task 9), and the
escalation rule engine (task 10) exist:

- The loose provider → `owner_target` SA path should surface as a
  **HIGH-confidence** `FEDERATES_WITH` edge (per the 3-tier model in
  `docs/THREAT_MODEL.md` §4) terminating at an `is_admin=True` node — the
  true positive.
- The scoped provider → `scoped_target` SA path should produce **no**
  escalation finding — the true negative. If the rule engine ever flags
  it, that's a bug in the rule engine, not a problem with this Terraform.

## Teardown

```bash
terraform destroy
```

Everything here is designed to be fully destroyable — the S3 bucket has
`force_destroy = true`, and `google_project_service` uses
`disable_on_destroy = false` so teardown never disables shared project
APIs out from under anything else in the sandbox project.

## State handling

Local backend, on purpose (solo sandbox project, no team to share state
with). `terraform.tfstate` will contain real AWS account IDs, GCP project
IDs, and resource ARNs once you apply — it is covered by the repo-root
`.gitignore`. Never commit it, never paste its contents into a public
issue/PR, and sanitize before any screenshot of `terraform output` goes
into `docs/` (SCOPE.md rule 5).
