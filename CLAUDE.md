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
- `docs/` — the public portfolio site (GitHub Pages, served from here)
- `SCOPE.md`, `TASKS.md` — read these first, always

## Current status

Check TASKS.md checkboxes for the authoritative current state. As of
last handoff: scope doc and threat model doc are both written
(`SCOPE.md`, `docs/THREAT_MODEL.md` — STRIDE analysis on the 3 trust
boundaries: cloud API, credential use, publication; plus the 5-pattern
escalation catalog and the 3-tier correlation confidence model). Next
up is external, not code: create the dedicated AWS + GCP sandbox
accounts and their least-privilege read-only credentials (tasks 3–5) —
`AWSCollector` can't run against a real account (task 7) and
`GCPCollector` can't be implemented for real (task 8) until those
exist. GCP collector is still a stub.
