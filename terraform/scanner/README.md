# Scanner credential policy — task 5 (AWS + GCP)

The least-privilege, read-only identities `AWSCollector` and
`GCPCollector` authenticate with — the enumerated form of `SCOPE.md`
rule 1's `iam:List*`/`iam:Get*` (AWS) / `cloudasset.viewer`-equivalent
(GCP) prose summary. Distinct from `terraform/track1/`/`track2/`/`track3/`,
which provision the *vulnerable sandbox infrastructure* the tool scans —
this provisions the *tool's own credentials*, a separate principal per
`SCOPE.md` rule 1.

**GCP half formalizes an identity already manually created and
validated** — the same `iam-pathfinder-scanner` service account
referenced throughout this repo's history, not new design.

## AWS: policy only, not a role/user

`aws.tf` — Why enumerated, not `iam:List*`/`iam:Get*` wildcards:
`iam:List*`/`iam:Get*` (what `SCOPE.md` describes informally) is broader
than the collector actually needs — it also grants list/get access to
unrelated IAM read APIs (access keys, SSH public keys, signing
certificates, service-specific credentials, etc.) that `AWSCollector`
never calls. This policy instead enumerates exactly the actions the
collector's boto3 calls use — see the action-to-call mapping in
`aws.tf`'s comments. If `AWSCollector` starts calling a new API, this
file needs a matching line, and vice versa; they're meant to stay in
lockstep, not drift.

Only the policy document (`aws_iam_policy.scanner_read_only`) — not a
role, user, or trust/attachment. How the credential itself gets
delivered to the tool (a static IAM user + access key, an assumable role
for CI, etc.) is still an open task-5 decision; attach this policy's ARN
to whichever identity that decision produces.

## GCP: a real service account, impersonation only — no key

`gcp.tf` creates the scanner service account itself (unlike the AWS
side, which is policy-only) plus three project-level role bindings:

| Role | Covers |
|---|---|
| `roles/cloudasset.viewer` | `SearchAllIamPolicies` (`GCPCollector._collect_iam_policy_bindings`) |
| `roles/iam.securityReviewer` | `serviceAccounts.list/get/getIamPolicy` |
| `roles/iam.workloadIdentityPoolViewer` | `workloadIdentityPools/-Providers.list` — **not** covered by `securityReviewer` alone |

**Deliberately no `google_service_account_key` resource anywhere in this
file.** Per `SCOPE.md`, no long-lived credentials are ever committed to
this repo, and more broadly this project authenticates via
impersonation (Application Default Credentials +
`roles/iam.serviceAccountTokenCreator`), never a downloaded key. The
`google_service_account_iam_member` binding grants `var.gcp_scanner_operator_email`
exactly that impersonation right — see `scripts/run_gcp_collector.py`
and this repo's earlier session notes for the actual
`gcloud auth application-default login --impersonate-service-account=...`
usage.

**IAM propagation delay, confirmed via real debugging**: the
impersonation binding needs a few minutes to actually take effect after
`terraform apply`. If impersonation fails immediately after applying,
that's propagation delay, not a broken config — wait a few minutes and
retry before assuming something in this Terraform is wrong.

## Usage

```bash
cd terraform/scanner
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your sandbox gcp_project_id / gcp_scanner_operator_email

terraform init
terraform plan
terraform apply
# AWS: attach the output scanner_read_only_policy_arn to your chosen scanner identity
# GCP: gcp_scanner_service_account_email is ready to impersonate immediately
#      (after the propagation delay noted above)
```

Same prerequisites/state-handling notes as `terraform/track1/README.md`
apply (sandbox-only credentials to *create* these identities, local
gitignored state, never a production/personal account).
