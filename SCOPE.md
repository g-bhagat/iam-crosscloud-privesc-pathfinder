# Scope and Rules of Engagement

## Objective

Build and validate a proof-of-concept tool that discovers privilege
escalation paths that cross the AWS↔GCP boundary via federated identity
trust (OIDC / Workload Identity Federation), which single-cloud CSPM/CIEM
tools do not detect because they analyze each cloud's identity graph in
isolation. See docs/THREAT_MODEL.md for the full risk rationale.

## Accounts in scope

- **AWS**: a dedicated free-tier AWS account, created specifically for
  this project. Not a production account, not a personal/work account
  used for anything else.
- **GCP**: a dedicated free-tier GCP project, created specifically for
  this project. Same isolation rule as above.

No other AWS account, GCP project, Azure tenant, or third-party service
is in scope. Azure is explicitly out of scope for implementation (see
"Out of scope" below).

## Rules of engagement

1. **Read-only credentials only, for the tool itself.** The scanning
   tool (collectors) authenticates using a purpose-built, least-privilege
   IAM identity in each cloud, scoped to read-only IAM/identity APIs --
   `iam:List*`/`iam:Get*`/`sts:GetCallerIdentity` is the informal summary;
   `terraform/scanner/aws.tf` is the actual enumerated policy (identity
   inventory, attached/inline policy inspection, and OIDC provider
   inventory via `iam:ListOpenIDConnectProviders`/`iam:GetOpenIDConnectProvider`)
   on AWS, `cloudasset.viewer` equivalent on GCP. The tool never has write
   or delete permissions on either account.
2. **All misconfigurations are deliberately planted, in these sandbox
   accounts only, by me.** Nothing in this project scans, probes, or
   references any account, tenant, or credential I do not own and did
   not set up for this purpose.
3. **No destructive actions**, at any point, from any component of the
   project — this includes the collectors, any validation scripts, and
   any manual testing.
4. **No real personal or company data** is stored in either sandbox
   account. Test resources use synthetic names and data only.
5. **Anything shared publicly (portfolio site, GitHub repo, screenshots)
   is sanitized first** — no real AWS account IDs, GCP project IDs,
   ARNs, or resource names that could identify the actual sandbox
   accounts. Placeholder/example values are used in all public-facing
   material.

## In scope (what gets built and demonstrated)

- AWS IAM identity collection (users, roles, groups, policies, trust
  policies) — `AWSCollector`
- GCP IAM identity collection (service accounts, IAM bindings, Workload
  Identity Federation pools/providers) — `GCPCollector`
- Cross-cloud correlation logic (the `FEDERATES_WITH` edge + 3-tier
  confidence model)
- Two fully validated use cases (see TASKS.md):
  - **Track 1**: CI/CD OIDC trust mismatch between AWS and GCP
  - **Track 2**: overly-broad GCP Workload Identity Federation trust of
    an AWS principal
- Escalation rule engine, pathfinder, and remediation output for both
  tracks
- A public-facing case study (portfolio site) presenting sanitized
  findings and remediation guidance

## Out of scope (deliberately deferred, not abandoned)

- **Azure** — no implementation, due to lack of a currently-validated
  Azure test environment. Documented at the methodology level only.
- **Mirror-direction AWS-trusts-GCP escalation** — same underlying
  detection logic as Track 2; low incremental value as a third
  demonstrated case.
- **Static credential leakage across the cloud boundary** — a distinct
  capability (secrets/content scanning vs. policy-graph traversal),
  better suited to a future extension.
- **DR/failover and cross-cloud SSO deprovisioning gaps** — deferred for
  sandbox-complexity reasons (multi-region setup / requires a real IdP
  tenant federated to both clouds).
- Any data-plane access analysis (S3 object contents, GCS bucket
  contents, etc.) — this project analyzes identity and permission
  structure, not data exposure.

## Success criteria

- Both tracks produce a **true positive**: the tool correctly identifies
  the planted escalation path, with correct blast-radius/severity
  reasoning.
- Both tracks include a **negative control**: a correctly-scoped,
  non-vulnerable configuration that the tool does *not* flag — proving
  the detection logic isn't just pattern-matching on the presence of
  federation, but on the specific misconfiguration.
- Each track produces a concrete remediation artifact (before/after
  policy diff) that would actually close the gap if applied.
- Findings are mapped to MITRE ATT&CK Cloud and at least one relevant
  NIST/CIS control per pattern.
- The threat model, scope doc, and TASKS.md are complete and accurate
  at the time the project is presented publicly — this doc is not
  written once and forgotten; if scope changes, this file changes too.

## Authorization

This is a self-directed learning/portfolio project against sandbox
accounts I created and own. In a real client or employer engagement,
this section would instead record written authorization from the
account/tenant owner before any scanning begins — noted here explicitly
because skipping that step in a real engagement is itself a serious
issue, not a formality.
