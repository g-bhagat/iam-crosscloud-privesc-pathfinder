# Scanner credential policy — task 5 (AWS half)

The least-privilege, read-only IAM policy `AWSCollector` authenticates
with — the enumerated form of `SCOPE.md` rule 1's `iam:List*`/`iam:Get*`
prose summary. Distinct from `terraform/track1/`, which provisions the
*vulnerable sandbox infrastructure* the tool scans — this provisions the
*tool's own credential*, a separate principal per `SCOPE.md` rule 1.

## Why enumerated, not `iam:List*`/`iam:Get*` wildcards

`iam:List*`/`iam:Get*` (what `SCOPE.md` describes informally) is broader
than the collector actually needs — it also grants list/get access to
unrelated IAM read APIs (access keys, SSH public keys, signing
certificates, service-specific credentials, etc.) that `AWSCollector`
never calls. This policy instead enumerates exactly the actions the
collector's boto3 calls use — see the action-to-call mapping in
`aws.tf`'s comments. If `AWSCollector` starts calling a new API, this
file needs a matching line, and vice versa; they're meant to stay in
lockstep, not drift.

## What's NOT here

Only the policy document (`aws_iam_policy.scanner_read_only`) — not a
role, user, or trust/attachment. How the credential itself gets
delivered to the tool (a static IAM user + access key, an assumable role
for CI, etc.) is still an open task-5 decision; attach this policy's ARN
to whichever identity that decision produces.

## Usage

```bash
cd terraform/scanner
terraform init
terraform plan
terraform apply
# then: attach the output policy_arn to your chosen scanner identity
```

Same prerequisites/state-handling notes as `terraform/track1/README.md`
apply (sandbox-only credentials to *create* this policy, local gitignored
state, never a production/personal account).
