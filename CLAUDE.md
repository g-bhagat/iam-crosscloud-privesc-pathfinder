# iam-crosscloud-privesc-pathfinder

Cross-cloud (AWS + GCP) IAM privilege escalation path analyzer. Portfolio
project for a cloud security architect role — the judgment/reasoning
(threat model, risk scoring, remediation tradeoffs) matters as much as
the working code. See @SCOPE.md and @TASKS.md before doing anything —
they are the source of truth for scope and sequencing, not this file.

## Scope (see SCOPE.md for full detail)

- AWS + GCP only. Azure is documented, not implemented (no validated
  Azure test env available).
- Three fully-built use cases (see TASKS.md "Track 1" / "Track 2" /
  "Track 3"). Static credential leakage, DR/failover, and cross-cloud
  SSO deprovisioning remain deliberately deferred — do not add them
  without discussing scope first.
- Read-only credentials only, against two dedicated sandbox accounts.
  Never touch a production, personal, or employer-owned account.
- No destructive actions anywhere in this project, ever.

## Working style

- Work through TASKS.md **in order, one task at a time**. Don't jump
  ahead to later tracks before the current one is validated end to end.
- Prefer Terraform for all sandbox infrastructure (AWS OIDC providers,
  IAM roles, GCP WIF pools, service accounts). Commit Terraform configs
  to version control; `terraform destroy` is the standard teardown.
- Every planted misconfiguration needs a paired, correctly-scoped
  negative control — the tool must prove a true negative, not just a
  true positive.
- No real account IDs, ARNs, or project IDs in anything committed to
  this repo or published on the portfolio site (docs/) — sanitize
  before it's public-facing.
- No long-lived credentials committed to this repo, ever.

## Structure

- `src/graph_schema.py` — unified node/edge schema shared across all collectors
- `src/collectors/` — AWS (real), GCP (real), Azure (stub, deferred)
- `src/analysis/` — correlation engine, confidence scoring, escalation rule engine, pathfinder (tasks 9-11)
- `src/visualization/` — pyvis graph export (task 12)
- `src/sanitize.py` — masks real account IDs/ARNs/project IDs and human user email addresses before anything reaches a published export; `pyvis_export.export_graph(..., sanitize=True)` opts in
- `sample_data/`, `scripts/generate_sample_graph.py`, `scripts/run_pipeline_demo.py` — synthetic Track 1-shaped fixture + end-to-end demo, used to validate tasks 9-12 without live sandbox credentials
- `scripts/run_aws_collector.py`, `scripts/run_gcp_collector.py` — run each real collector against its real sandbox; meant to be run locally where real credentials/ADC are already set up, not from this sandboxed session
- `scripts/run_detector.py` — task 19's real-data pipeline (both collectors' JSON dumps → correlation → escalation rules → pathfinder → pyvis export); auto-sanitizes whenever `--output` resolves under `docs/`
- `tests/` — pytest suite for the analysis layer
- `terraform/track1/` — AWS + GCP sandbox infra for Track 1 (tasks 13-18); written, not yet applied/validated against live accounts
- `terraform/track2/` — GCP-trusts-AWS-directly sandbox infra for Track 2 (tasks 24-30); formalizes infra already manually built and live-validated (real token exchange, real Finding fired) — written, not yet applied from this repo's Terraform
- `terraform/track3/` — AWS-trusts-GCP-directly sandbox infra for Track 3 (tasks 35-39); same status as track2 — formalizes already-validated manual infra, not yet applied from this repo's Terraform
- `terraform/scanner/` — the tool's own least-privilege read-only scanner credential, both AWS and GCP halves (task 5); written, not yet applied
- `docs/` — the public portfolio site (GitHub Pages, served from here)
- `SCOPE.md`, `TASKS.md` — read these first, always

## Current status

Check TASKS.md checkboxes for the authoritative current state — this
section is a snapshot, not a running log. For the history of what got
fixed and why, use `git log`, not this file.

**Code-complete and tested** (synthetic data, and real-shaped output
from both collectors — see `tests/`): `graph_schema.py`, `AWSCollector`,
`GCPCollector`, the correlation engine + 3-tier confidence scoring, the
escalation rule engine (all three patterns), the pathfinder, the pyvis
export, and `src/sanitize.py`. None of this has been validated against
a live sandbox account yet — no moto-equivalent exists for GCP, so
`GCPCollector` is validated via mocks built against the real
`google-cloud-asset`/`google-api-python-client` response shapes rather
than a full-service fake.

**Blocked on external setup, not code**: the dedicated AWS sandbox
account and GCP sandbox project (tasks 3–4) don't exist yet. Everything
downstream of that — applying any Terraform, running the collectors
against a real account, live true-positive/true-negative validation for
any track — is written and ready but un-run from this repo. Manual
`terraform apply`/`destroy` against real cloud accounts is intentionally
kept off this agent; a human runs that step.

**Terraform**: written for the scanner credential and all three tracks
(`terraform/scanner/`, `terraform/track1/`, `terraform/track2/`,
`terraform/track3/`) — formatted (`terraform fmt`) and manually
cross-checked (variable coverage, no dangling references) since
`terraform init`/`validate` can't reach the provider registry from this
session. Track 2 and Track 3's underlying misconfigurations were
separately built and live-validated by hand outside this repo before
being formalized here (real AWS↔GCP token exchanges succeeded, real
Findings fired through the actual detection pipeline); Track 1 has not
yet been validated live at all, by hand or otherwise.
