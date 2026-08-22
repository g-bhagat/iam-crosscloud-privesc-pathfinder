# iam-crosscloud-privesc-pathfinder

Cross-cloud (AWS + GCP) IAM privilege escalation path analyzer. Portfolio
project for a cloud security architect role — the judgment/reasoning
(threat model, risk scoring, remediation tradeoffs) matters as much as
the working code. See @SCOPE.md and @TASKS.md before doing anything —
they are the source of truth for scope and sequencing, not this file.

## Scope (see SCOPE.md for full detail)

- AWS + GCP only. Azure is documented, not implemented (no validated
  Azure test env available).
- Two fully-built use cases only (see TASKS.md "Track 1" / "Track 2").
  A third use case and static credential leakage were deliberately
  deferred — do not add them without discussing scope first.
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
- `src/collectors/` — AWS (real), GCP (stub, needs implementation), Azure (stub, deferred)
- `src/analysis/` — correlation engine, confidence scoring, escalation rule engine, pathfinder (tasks 9-11)
- `src/visualization/` — pyvis graph export (task 12)
- `sample_data/`, `scripts/generate_sample_graph.py`, `scripts/run_pipeline_demo.py` — synthetic Track 1-shaped fixture + end-to-end demo, used to validate tasks 9-12 without live sandbox credentials
- `tests/` — pytest suite for the analysis layer
- `terraform/track1/` — AWS + GCP sandbox infra for Track 1 (tasks 13-18); written, not yet applied/validated against live accounts
- `docs/` — the public portfolio site (GitHub Pages, served from here)
- `SCOPE.md`, `TASKS.md` — read these first, always

## Current status

Check TASKS.md checkboxes for the authoritative current state. As of
last handoff: Phase 0 is code-complete except for the live-credential
tasks. Done: scope + threat model docs (`SCOPE.md`, `docs/THREAT_MODEL.md`),
`graph_schema.py`, and the full analysis layer (`src/analysis/`,
`src/visualization/pyvis_export.py`, tasks 9-12) — validated end to end
against a synthetic Track 1-shaped graph (`sample_data/sample_graph.json`,
`scripts/run_pipeline_demo.py`), confirming both the true positive (loose
GCP WIF provider → `roles/owner` SA) and the true negative (correctly
scoped control) at the correlation + rule-engine + pathfinder level.
Track 1 Terraform (`terraform/track1/`) is also written but not yet
applied. Still blocked on external setup, not code: create the dedicated
AWS + GCP sandbox accounts and their least-privilege read-only
credentials (tasks 3–5) — `AWSCollector` can't run against a real account
(task 7) and `GCPCollector` can't be implemented for real (task 8) until
those exist; the analysis layer's real-data validation depends on both.
