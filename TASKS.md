# Task list — Multi-Cloud IAM Privilege Escalation Path Analyzer (AWS + GCP)

Scope: AWS + GCP only, three fully-built use cases. Azure is documented as
in-scope for the methodology but deliberately deferred for implementation
(no current validated Azure test environment). Static credential leakage,
DR/failover, and cross-cloud SSO deprovisioning were considered and
deliberately deferred — see "Deferred (documented, not built)" below.
Mirror-direction AWS-trusts-GCP was originally deferred too, then
un-deferred as Track 3 — see SCOPE.md "Reversed decisions" for why.
See docs/THREAT_MODEL.md for the full rationale and the escalation-pattern
catalog these tasks implement.

Sequencing rule: build Phase 0 + Track 1 as one complete vertical slice
before starting Track 2, and Track 2 before Track 3. Don't parallelize
until each prior use case works end to end against real sandbox data.

---

## Phase 0 — Shared foundation

- [x] 1. Write the scope / rules-of-engagement doc — done (`SCOPE.md`)
- [x] 2. Write the threat model doc (trust boundaries, 5 escalation paths, correlation confidence tiers) — done (`docs/THREAT_MODEL.md`)
- [ ] 3. Create a dedicated AWS free-tier sandbox account
- [ ] 4. Create a dedicated GCP free-tier project
- [ ] 5. Create a least-privilege, read-only scanning credential in each cloud — AWS policy written (`terraform/scanner/aws.tf`), not applied; GCP side not started
- [x] 6. `graph_schema.py` — done
- [ ] 7. Get `AWSCollector` running against the real sandbox account, debug against live API responses — validated against a moto-mocked AWS account (`tests/test_aws_collector.py`, `tests/test_collector_correlation_integration.py`); real sandbox validation still pending task 3
- [x] 8. Implement `GCPCollector` for real — done (`src/collectors/gcp_collector.py`); validated against real API response shapes via mocked unit tests (`tests/test_gcp_collector.py`, 15 cases: service accounts, user-managed keys, WIF pool/provider bridging, the loose/scoped Track 1 bindings, CAI-based is_admin flagging) since no moto-equivalent exists for GCP; `scripts/run_gcp_collector.py` written for live validation against the real sandbox project, to be run locally where ADC is already set up — not yet run against the real project from this session
- [x] 9. Build the correlation engine (`FEDERATES_WITH` edge detector + 3-tier confidence logic) — done (`src/analysis/correlation.py`, `src/analysis/confidence.py`); validated against synthetic Track 1-shaped data (`sample_data/sample_graph.json`) AND against real (mocked, not hand-crafted) output from both collectors together (`tests/test_collector_correlation_integration.py`); true live-account validation still pending tasks 3-5
- [x] 10. Build the escalation rule engine (encode the 5 patterns as graph-pattern checks) — done (`src/analysis/escalation_rules.py`); Patterns 1-2 implemented, Patterns 3-5 stubbed as deferred per SCOPE.md
- [x] 11. Build the pathfinder (graph walk from any node to an `is_admin=True` node) — done (`src/analysis/pathfinder.py`, networkx-based)
- [x] 12. Build the pyvis visualization export — done (`src/visualization/pyvis_export.py`, `src/sanitize.py`); `sanitize=True` masks real account IDs/ARNs/project IDs, wired in automatically by `scripts/run_detector.py` whenever `--output` resolves under `docs/`; self-loop capability markers merge into one edge per node and zero-degree nodes are hidden by default so a real AdministratorAccess/roles/owner holder does not render as a knot of overlapping loops; a fixed corner annotation on the artifact itself states the scope boundary (escalation-relevant capabilities only, not a full IAM permissions inventory)

---

## Track 1 — CI/CD OIDC mismatch (build this end-to-end first)

- [ ] 13. Create a GitHub repo to act as the "victim" CI/CD pipeline
- [ ] 14. Add a GitHub Actions workflow with `id-token: write` permission
- [ ] 15. Configure AWS OIDC provider + role trust policy, correctly scoped (control / safe config)
- [ ] 16. Configure GCP WIF pool + provider trusting the same repo, deliberately loose `attribute-condition` (planted misconfiguration)
- [ ] 17. Grant AWS role moderate permission; bind GCP WIF provider to a service account with `roles/owner`
- [ ] 18. Set up a second, correctly-scoped WIF binding as a negative control (must NOT be flagged)
- [ ] 19. Run full pipeline (collectors → graph → correlation → escalation rules → pathfinder) against sandbox
- [ ] 20. Confirm true positive on the misconfigured path AND true negative on the clean control
- [ ] 21. Write remediation output (attribute-condition before/after diff)
- [ ] 22. Capture sanitized screenshots/diagram for the portfolio site
- [ ] 23. Write up the full worked case study doc

---

## Track 2 — Overly-broad GCP WIF trust of an AWS principal (reuses Track 1 infra)

- [ ] 24. Add a second WIF pool/provider trusting the same AWS account, scoped only to account ID (missing role-level scoping) — planted misconfiguration
- [ ] 25. Bind it to a second, high-privilege GCP service account
- [ ] 26. (No new collector work — same AWS/GCP collectors, same correlation engine)
- [ ] 27. Extend escalation rule engine: detect WIF conditions missing role-ARN scoping
- [ ] 28. Validate true positive + true negative (vs. a correctly scoped comparison binding)
- [ ] 29. Write remediation before/after (CEL condition diff)
- [ ] 30. Write up case study

---

## Track 3 — Mirror-direction AWS-trusts-GCP (the structurally airtight case)

An AWS role's trust policy accepts `AssumeRoleWithWebIdentity` calls
validated against Google's OIDC issuer (`accounts.google.com`) — AWS's
outbound identity federation, the reverse of Track 2's mechanism. This
is the pattern where the target's privilege (`is_admin` on the AWS
role) is only computable from AWS's own data — a GCP-only tool cannot
determine it, regardless of how well it reads its own WIF/IAM data.
See SCOPE.md "Reversed decisions" for the full reasoning.

- [ ] 35. Register an AWS IAM OIDC identity provider trusting `https://accounts.google.com`
- [ ] 36. Create an AWS role with a trust policy scoped only to the issuer + audience, missing a `sub` (subject) condition for a specific GCP service account — planted misconfiguration; grant it an admin-equivalent AWS policy so `is_admin=True`
- [ ] 37. Create a second AWS role with a correctly scoped trust condition (matches one specific GCP service account email in `sub`) — negative control
- [ ] 38. On the GCP side: an ordinary-looking service account with no notable GCP permissions of its own (the point being it looks unremarkable from GCP's perspective) that can generate identity tokens
- [ ] 39. From GCP, call `AssumeRoleWithWebIdentity` using that SA's identity token to confirm the path is real, not just a theoretical config
- [x] 40. Fix `check_pattern2`'s hardcoded `pattern_name`/`pattern_id` — done (`src/analysis/escalation_rules.py`); confirmed the matching logic was already direction-agnostic, so the fix is a `_DIRECTION_LABELS` map keyed on `target.cloud` (GCP target → pattern_id 2, AWS target → pattern_id 3) applied inside the single existing rule function — no new pattern function, no duplicated match logic. `DEFERRED_PATTERNS`/`run_all()` updated so pattern 3 no longer reports as skipped. New synthetic GCP→AWS test in `tests/test_escalation_rules.py` mirrors the existing pattern-2 test with the direction reversed; still no real Track 3 sandbox data (tasks 35-39 below), so end-to-end validation against a live misconfigured role is still pending
- [ ] 41. Validate true positive (misconfigured role) + true negative (scoped control)
- [ ] 42. Write remediation before/after (trust policy `sub` condition diff)
- [ ] 43. Write up case study — explicitly framed around why this is the structurally necessary case, not just another example

---

## Deferred (documented, not built)

These are real, catalogued escalation patterns — written up in the threat
model with mechanism, precondition, and blast radius — but deliberately
not implemented in the reference build.

- **Static credential leakage across the cloud boundary** (a GCP key
  stored as a static AWS secret, or vice versa): a genuinely different
  capability (content/secrets scanning, not policy-graph traversal) —
  better suited to a future extension than this reference build.
- **DR/failover identity** and **cross-cloud SSO deprovisioning gap**:
  deferred earlier for sandbox-complexity reasons (multi-region setup /
  requires a real IdP tenant wired to both clouds).
- **Compound/chained scenarios** (both clouds independently misconfigured
  from the same originating identity — does the pathfinder find one
  chained path, or two independent findings?): worth testing via
  `scripts/explore_scenarios.py` before deciding whether it needs new
  sandbox infrastructure or a pathfinder code change. Not yet a track.

---

## Wrap-up

- [ ] 44. Full validation pass across all three tracks together — confirm no cross-contamination between detectors
- [ ] 45. Write consolidated remediation report / executive summary
- [ ] 46. Write operationalization section (how this runs on a schedule in a real org)
- [ ] 47. Assemble portfolio website content from the case studies (hero visual, problem statement, architecture diagram, one worked example per track, remediation before/after, framework mapping, deferred-scope note, repo link)
