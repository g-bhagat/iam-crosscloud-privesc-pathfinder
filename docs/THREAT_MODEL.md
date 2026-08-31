# Threat Model

Companion to [`SCOPE.md`](../SCOPE.md) and [`TASKS.md`](../TASKS.md). Where
those docs define *what* is being built and in what order, this doc explains
*why* it matters: the trust boundaries this project itself crosses, the
three escalation paths it's designed to detect, and the confidence model
used to avoid false positives when correlating identities across clouds.

This is a living document — Phase 0 task list item 2. If scope changes,
this file changes with it (per `SCOPE.md`'s own rule). It documents what
this project actually builds and detects — three patterns, all three now
implemented in code and formalized in Terraform. Other cross-cloud gaps
(static credential leakage, DR/failover identity, cross-cloud SSO
deprovisioning) were considered and are tracked as deferred scope in
`SCOPE.md`; they are not modeled here.

---

## 1. Why cross-cloud federation is a distinct risk class

Single-cloud CSPM/CIEM tools build an identity graph scoped to one cloud's
control plane. Each tool correctly resolves privilege escalation *within*
that cloud (e.g. AWS `iam:PassRole` chains, GCP `serviceAccountTokenCreator`
chains). What none of them do is follow an edge that leaves their cloud.

OIDC federation and Workload Identity Federation exist specifically to let
a principal in one trust domain authenticate into another without a
long-lived credential — which is good practice compared to static keys, but
it also means the *actual* holder of a permission in Cloud B is a subject
string evaluated by Cloud A's trust policy, which most reviewers read as
prose, not as code. A GCP WIF provider's `attribute_condition` and an AWS
role's `AssumeRolePolicyDocument` `Condition` block are both, functionally,
authorization logic — but they're reviewed (if at all) by a single-cloud
IAM auditor who never opens the other cloud's console. That review gap is
the vulnerability this project targets: it is structural, not a bug in
either cloud's IAM, and it gets worse as federation adoption grows (every
CI/CD pipeline doing keyless cloud deploys is a new cross-cloud edge).

---

## 2. Trust boundaries in this project

Three trust boundaries apply — one is the subject of the analysis (the
cloud API boundary crossed by federation), and two are trust boundaries
*of the tool itself* that a security-architect-grade project has to reason
about explicitly rather than assume away.

### TB1 — Cloud API boundary (the object of study)

The boundary between an identity's home cloud and the cloud it federates
into: a GitHub Actions runner's OIDC token crossing into AWS via
`sts:AssumeRoleWithWebIdentity`, a workload's federated token crossing into
GCP via a Workload Identity Federation pool, or a GCP service account's
identity token crossing into AWS the same way. This is not a boundary the
*tool* defends — it's the boundary the tool exists to map and evaluate,
because it's evaluated correctly by neither side's native tooling in
isolation.

| STRIDE          | Applies? | Reasoning |
|-----------------|----------|-----------|
| Spoofing        | Yes | A workload whose OIDC `sub`/`aud` claims satisfy an overly-broad condition can spoof the identity the trust relationship intended to scope to (Track 1: any workflow in a trusted repo, not just the intended one; Track 2: any principal in a trusted AWS account, not just the intended role; Track 3: any GCP principal that can generate a Google identity token for the right audience, not just the intended service account). |
| Tampering       | No (out of scope) | Requires compromising the OIDC token issuer itself (GitHub's, AWS's, or Google's), not a misconfiguration this tool detects. |
| Repudiation      | Partial | Federated actions land in each cloud's own audit log (CloudTrail / Cloud Audit Logs) under the *assumed* identity, not the originating one — correlating the two requires this project's cross-cloud graph, which is itself a detective control this tool contributes. |
| Information Disclosure | Yes (consequence, not mechanism) | The actual harm of a successful escalation — reachable via the pathfinder's blast-radius reasoning, not analyzed as its own boundary here. |
| Denial of Service | No (out of scope, and explicitly forbidden — see `SCOPE.md` rule 3) | This tool never takes an action capable of causing it. |
| Elevation of Privilege | **Yes — this is the core finding class** | Track 1, Track 2, and Track 3 are all EoP: a principal that should only reach a moderate-privilege identity in its home cloud reaches an admin/owner-equivalent identity in the *other* cloud because the trust condition under-scopes who it accepts. |

### TB2 — Credential-use boundary (the tool's own execution)

The boundary between the tool's own scanning credentials and the sandbox
accounts they read from. This is the boundary `SCOPE.md` rule 1 exists to
control.

| STRIDE          | Applies? | Mitigation |
|-----------------|----------|------------|
| Spoofing        | Low | Credentials are scoped to a purpose-built IAM identity per cloud (task 5); no shared/ambient credentials, and impersonation only — no downloaded service account key on the GCP side (`terraform/scanner/gcp.tf`). |
| Tampering       | N/A | Read-only (`List*`/`Get*`, `cloudasset.viewer`-equivalent) — no write path exists to tamper with. |
| Repudiation      | Low | Each cloud's own audit trail (CloudTrail, Cloud Audit Logs) records every collector call under a distinctly-named identity, not a shared one. |
| Information Disclosure | **Primary risk here** | The collected graph contains real account IDs, ARNs, and project IDs. It must never leave the local working environment un-sanitized — this is what feeds TB3 below. |
| Denial of Service | Forbidden by design | `SCOPE.md` rule 3: no destructive action, ever, from any component including validation scripts. Read-only IAM scope enforces this at the permission layer, not just by convention. |
| Elevation of Privilege | **Structurally prevented** | The scanning identity itself must never be a viable escalation source — i.e. it must not appear as a `CAN_ASSUME`/`CAN_IMPERSONATE`/`FEDERATES_WITH` source in its own account's graph. Worth an explicit self-check once live sandbox data exists (candidate addition to the wrap-up validation pass, task 44). |

### TB3 — Publication boundary (repo + portfolio site)

The boundary between raw findings (real sandbox account IDs, ARNs, project
IDs, screenshots) and anything committed to this repo or published to the
`docs/` portfolio site. `SCOPE.md` rule 5 and the sanitization requirement
in `CLAUDE.md` both exist for this boundary.

| STRIDE          | Applies? | Mitigation |
|-----------------|----------|------------|
| Spoofing        | N/A | Not applicable to static published content. |
| Tampering       | Low | Standard repo/branch-protection hygiene; not a novel risk this project introduces. |
| Repudiation      | N/A | Not applicable. |
| Information Disclosure | **Primary risk here** | A raw graph export, an unredacted screenshot, or a copy-pasted ARN in a case-study writeup would identify the actual sandbox accounts. `src/sanitize.py` closes most of this automatically (`pyvis_export.export_graph(..., sanitize=True)`, forced on by `scripts/run_detector.py` whenever `--output` resolves under `docs/`) — but every artifact that reaches `docs/` (case studies, diagrams, sample graph exports) should still be treated as a checklist item at each track's screenshot/case-study task (22, 29, 43) and at final portfolio assembly (task 47), not assumed sanitized. |
| Denial of Service | N/A | Not applicable to a static site. |
| Elevation of Privilege | N/A | Publishing findings doesn't grant anyone privilege; it *documents* a privilege path that has already been remediated (per the success criteria in `SCOPE.md`, remediation ships with the finding, so the published misconfiguration is a historical before/after, not a live one). |

---

## 3. The three cross-cloud escalation paths

Three structurally distinct escalation mechanisms, all implemented: the
detection logic (collectors → correlation → escalation rules → pathfinder)
exists and is tested for each; the sandbox infrastructure that plants each
misconfiguration is formalized in Terraform. See `TASKS.md` checkboxes for
exactly which tasks are done versus still pending live-account validation —
this document covers the mechanism, not the build-tracking detail.

Framework references use MITRE ATT&CK for Cloud (`attack.mitre.org`, Cloud
matrix) and NIST SP 800-53 / CIS Controls v8, as required by `SCOPE.md`'s
success criteria.

### Pattern 1 — CI/CD OIDC trust mismatch (Track 1)

- **Mechanism:** A CI/CD workflow (GitHub Actions) is trusted by both an
  AWS IAM role (via an OIDC provider + role trust policy) and a GCP
  service account (via a Workload Identity Federation pool/provider). The
  AWS side is correctly scoped (control config); the GCP WIF provider's
  `attribute_condition` is planted with a loose match — trusting the
  issuer/subject pattern broadly rather than pinning the specific
  repo+branch the AWS side pins.
- **Precondition:** Any workflow able to satisfy the loose GCP-side
  condition (e.g. any workflow in the org, not just the intended repo) can
  mint a token impersonating the bound GCP service account.
- **Blast radius:** The GCP WIF provider is bound to a service account
  with `roles/owner` — full project control from a workload that was only
  ever supposed to reach a moderate-privilege AWS role.
- **MITRE ATT&CK Cloud:** T1550.001 (Use Alternate Authentication Material
  — Application Access Token), via TA0004 (Privilege Escalation) through a
  trust-relationship abuse consistent with T1199 (Trusted Relationship).
- **NIST/CIS:** NIST SP 800-53 AC-3 (Access Enforcement) / CIS Control 5.4
  (restrict administrative privileges) and CIS Control 6.8 (define and
  maintain role-based access, applied to federated/non-human identities).
- **Why this is the structurally necessary case:** Of the three patterns,
  this is the only one where neither cloud's own data contains any
  reference to the other cloud's trust at all — GitHub is a genuine third
  party, trusted independently by AWS and GCP, and only correlating both
  clouds' collected graphs (`correlation.merge_oidc_bridges`) surfaces the
  relationship. Patterns 2 and 3 are direct cloud-to-cloud trust — a single
  cloud's own data at least names the other cloud as the counterparty.
- **Status:** Detection logic implemented and validated end-to-end against
  synthetic data (`sample_data/sample_graph.json`,
  `scripts/run_pipeline_demo.py`). Terraform sandbox infrastructure written
  (`terraform/track1/`); not yet applied to a live account — pending
  dedicated AWS/GCP sandbox accounts (tasks 3–4) and live validation
  (tasks 19–20).

### Pattern 2 — Overly-broad GCP WIF trust of an AWS principal (Track 2)

- **Mechanism:** A GCP Workload Identity Federation pool/provider trusts
  AWS directly as an identity provider (an `aws { account_id = ... }`
  provider, not an OIDC issuer) but scopes the trust only to the AWS
  account ID — no `attribute_condition` narrowing which role ARN within
  that account is accepted.
- **Precondition:** Any IAM principal capable of signing a valid AWS
  request in the trusted account can exchange it for a GCP federated
  token — not just the specific role the binding was intended for.
- **Blast radius:** Bound to a high-privilege GCP service account
  (`roles/owner`) — effectively, every role in the AWS account becomes a
  path to that GCP privilege level, not just the one role that was
  supposed to have it.
- **MITRE ATT&CK Cloud:** T1199 (Trusted Relationship) combined with
  T1078.004 (Valid Accounts: Cloud Accounts) — the escalation doesn't
  require compromising a credential, only holding *any* sufficiently
  ordinary one in the trusted account.
- **NIST/CIS:** NIST SP 800-53 AC-6 (Least Privilege) — the missing
  role-level condition is a textbook least-privilege violation applied to
  a federation trust rather than a role policy. CIS Control 3.3 (configure
  data access control lists) as the general "scope trust to the minimum
  needed" analogue.
- **Status:** Detection logic implemented and validated the same way as
  Pattern 1, plus against real (mocked) `GCPCollector` output
  (`tests/test_gcp_collector.py`, `tests/test_collector_correlation_integration.py`).
  The underlying misconfiguration was manually built and live-validated
  outside this repo — a real AWS→GCP token exchange succeeded, and a real
  Finding fired through the actual detection pipeline — before being
  formalized into Terraform (`terraform/track2/`); not yet applied from
  this repo's Terraform specifically.

### Pattern 3 — Mirror-direction AWS-trusts-GCP (Track 3)

- **Mechanism:** An AWS IAM role's trust policy accepts
  `sts:AssumeRoleWithWebIdentity` calls from Google's built-in web
  identity provider — a bare `"accounts.google.com"` `Federated`
  principal, not an ARN (Google is one of AWS's natively-recognized
  providers, alongside Cognito, Amazon, and Facebook; registering an OIDC
  provider resource for it is the wrong mechanism and produces
  `InvalidIdentityToken` regardless of everything else being correctly
  configured). The trust condition checks only the audience
  (`accounts.google.com:oaud`, not `:aud` — AWS's `:aud` condition key
  actually checks the token's `azp` claim), with no
  `accounts.google.com:sub` condition narrowing which GCP principal's
  token is accepted.
- **Precondition:** Any GCP principal capable of generating a Google
  identity token audienced to `sts.amazonaws.com` can assume the role —
  not just the one service account the trust was meant to scope to.
- **Blast radius:** The role carries `AdministratorAccess` — full AWS
  account control from a GCP service account that, by design, looks
  unremarkable from GCP's own side (no notable GCP permissions of its
  own).
- **MITRE ATT&CK Cloud:** T1199 (Trusted Relationship) + T1078.004 (Valid
  Accounts: Cloud Accounts) — same mapping as Pattern 2, mirrored
  direction.
- **NIST/CIS:** NIST SP 800-53 AC-6 (Least Privilege) — the missing `sub`
  condition is the same class of gap as Pattern 2's missing role-level
  condition, on AWS's inbound-trust side instead of GCP's. CIS Control
  3.3.
- **Why this pattern, not just "Pattern 2 again":** Not the structurally
  cross-cloud-necessary case (see Pattern 1 above) — an AWS-only tool can
  determine this role's `is_admin` status and read its own trust condition
  using only AWS-native data, the same limitation Pattern 1's GCP-side
  check has, just mirrored (see `SCOPE.md` "Reversed decisions" for the
  full history: this was originally justified on the opposite, incorrect
  claim). Its value is narrower and more honest: it's a distinct, less
  commonly audited misconfiguration class (AWS's newer outbound identity
  federation feature), and it completes the secure/insecure combination
  matrix across both trust directions rather than testing only one.
- **Status:** Detection logic implemented (`escalation_rules.py`'s
  direction-aware `pattern_id=3` labeling) and validated against real
  (mocked) `AWSCollector` output (`tests/test_escalation_rules.py`,
  `tests/test_collector_correlation_integration.py`). The underlying
  misconfiguration was manually built and live-validated outside this
  repo — a real GCP→AWS token exchange succeeded, and a real Finding
  fired through the actual detection pipeline — before being formalized
  into Terraform (`terraform/track3/`); not yet applied from this repo's
  Terraform specifically, and dedicated sandbox accounts (tasks 3–4)
  don't exist yet.

---

## 4. Correlation confidence tiers

The correlation engine (`src/analysis/correlation.py`) is what actually
draws a `FEDERATES_WITH` edge between an AWS-side trust statement and a
GCP-side WIF binding, in either direction. Not every apparent match is
equally trustworthy — a naming coincidence is not the same evidence as a
cryptographically meaningful match — so every `FEDERATES_WITH` edge
carries a confidence tier that downstream severity scoring (`risk_weight`)
and the escalation rule engine both key off of. This is what lets the tool
prove a true negative (`SCOPE.md` success criteria) rather than just
pattern-matching on federation's mere presence.

| Tier | Criteria | Example | Effect on scoring |
|------|----------|---------|--------------------|
| **HIGH** | Structural match: the trust condition on the resolving side pins a specific repo+branch, a specific role ARN, or a specific GCP principal's subject ID — precise enough that only one intended identity can traverse the edge. | Track 1's negative control (`assertion.repository == ... && assertion.ref == ...`); Track 2's negative control (`assertion.arn.startsWith('.../assumed-role/<role>/')`); Track 3's negative control (`accounts.google.com:sub` pinned to one GCP service account's numeric ID). | Edge is treated as a correctly-scoped control, not a finding, even when the target is high-privilege — this is what proves the true negative. Full `risk_weight` applied for pathfinder traversal cost purposes, but `escalation_rules.py` does not flag it. |
| **MEDIUM** | Partial/structural match: the relationship is real and federation-based, but scoping is coarser than role/subject level on the resolving side — e.g. account-ID-only trust, or an audience-only check with no subject pin. | The Track 2 misconfiguration: GCP WIF trusts an AWS account ID with no role-level condition. The Track 3 misconfiguration: AWS trusts `accounts.google.com` with no `sub` condition. In both, the edge is real, but which specific principal it resolves to is a *set*, not a single identity. | Flagged as a finding when the target is high-privilege — this is the actual vulnerability signature for Patterns 2 and 3, so MEDIUM confidence in *precision* is exactly what HIGH-risk findings look like here. |
| **LOW** | Heuristic/inferred: no structural linkage confirmed by either cloud's actual trust configuration — e.g. the same repo name, project name, or naming convention appears on both sides, suggesting a relationship a human likely intended, but nothing in either policy document actually encodes it. | A GCP service account named `gh-actions-deploy-sa` and an AWS role named `github-actions-deploy-role` exist in accounts known to belong to the same org, but neither has a federation binding to the other yet (or the binding uses a generic issuer with no distinguishing condition at all). | Surfaced only as an *advisory* note ("possible intended pairing, not a live trust relationship") — never treated as a `FEDERATES_WITH` edge the pathfinder traverses, and never contributes to a finding. Exists so the tool can flag naming-convention drift as a hygiene note without inflating the escalation-path count with guesses. |

The tiering is deliberately conservative: a LOW-confidence guess is *never*
promoted into pathfinder traversal, only HIGH and MEDIUM are — because a
false positive on a security tool's headline finding is more damaging to
its credibility (and, in a real engagement, to the analyst's time) than a
missed LOW-confidence hint that's surfaced separately as a hygiene note.

---

## 5. Assumptions and limitations

- **Policy evaluation is heuristic, not exhaustive.** Per the docstring in
  `aws_collector.py`, this project uses action-name-based heuristics
  (à la Cloudsplaining), not full IAM policy simulation. It will miss
  escalation paths gated by conditions it doesn't model, and it may flag
  a technically-present-but-effectively-unreachable action as a finding.
  Acceptable for a portfolio-grade posture assessment; would need
  strengthening (e.g. integrating an actual policy simulator) before use
  in a real engagement.
- **Two clouds, two accounts, three use cases.** Findings generalize to
  the *pattern*, not to any specific organization's environment — this is
  a reference build against synthetic, self-planted misconfigurations,
  not a live audit of a real org's cross-cloud posture.
- **Azure is a documentation-only gap**, not a modeling gap —
  `graph_schema.py` and the escalation catalog above are cloud-agnostic by
  design, and `azure_collector.py` exists as a structurally complete stub
  specifically so wiring up a real Azure tenant later doesn't require
  touching the schema, correlation engine, or rule engine.
- **This threat model does not cover the analysis code's own supply
  chain** (dependency compromise of `boto3`, `google-cloud-asset`, etc.) —
  standard dependency-hygiene practice applies and isn't specific enough
  to this project's thesis to warrant its own trust boundary here.
