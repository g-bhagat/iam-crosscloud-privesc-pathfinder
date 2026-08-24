# Task list — Multi-Cloud IAM Privilege Escalation Path Analyzer (AWS + GCP)

Scope: AWS + GCP only, two fully-built use cases. Azure is documented as
in-scope for the methodology but deliberately deferred for implementation
(no current validated Azure test environment). A third use case (mirror-
direction AWS-trusts-GCP) and static credential leakage were considered
and deliberately deferred — see "Deferred (documented, not built)" below —
in favor of going deep on two structurally distinct mechanisms rather than
shallow on three. See docs/THREAT_MODEL.md (once written) for the full
rationale and the escalation-pattern catalog these tasks implement.

Sequencing rule: build Phase 0 + Track 1 as one complete vertical slice
before starting Track 2. Don't parallelize until one use case works end
to end against real sandbox data.

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

## Deferred (documented, not built)

These are real, catalogued escalation patterns — written up in the threat
model with mechanism, precondition, and blast radius — but deliberately
not implemented in the reference build, to keep scope tight around two
fully-validated use cases rather than three partially-validated ones.

- **Mirror-direction AWS-trusts-GCP** (AWS outbound identity federation via
  `AssumeRoleWithWebIdentity` against Google's OIDC): same underlying
  detection logic as Track 2 (missing subject-level scoping), just checked
  on the other side of the trust relationship — low incremental value as
  a third case.
- **Static credential leakage across the cloud boundary** (a GCP key
  stored as a static AWS secret, or vice versa): a genuinely different
  capability (content/secrets scanning, not policy-graph traversal) —
  better suited to a future extension than this reference build.
- **DR/failover identity** and **cross-cloud SSO deprovisioning gap**:
  deferred earlier for sandbox-complexity reasons (multi-region setup /
  requires a real IdP tenant wired to both clouds).

---

## Wrap-up

- [ ] 31. Full validation pass across both tracks together — confirm no cross-contamination between detectors
- [ ] 32. Write consolidated remediation report / executive summary
- [ ] 33. Write operationalization section (how this runs on a schedule in a real org)
- [ ] 34. Assemble portfolio website content from the case studies (hero visual, problem statement, architecture diagram, one worked example, remediation before/after, framework mapping, deferred-scope note, repo link)
