# Threat Model

Companion to [`SCOPE.md`](../SCOPE.md) and [`TASKS.md`](../TASKS.md). Where
those docs define *what* is being built and in what order, this doc explains
*why* it matters: the trust boundaries this project itself crosses, the
escalation-path catalog it's designed to detect, and the confidence model
used to avoid false positives when correlating identities across clouds.

This is a living document — Phase 0 task list item 2. If scope changes,
this file changes with it (per `SCOPE.md`'s own rule).

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
prose, not as code. A GCP WIF provider's `attribute-condition` and an AWS
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
`sts:AssumeRoleWithWebIdentity`, or a workload's federated token crossing
into GCP via a Workload Identity Federation pool. This is not a boundary
the *tool* defends — it's the boundary the tool exists to map and evaluate,
because it's evaluated correctly by neither side's native tooling in
isolation.

| STRIDE          | Applies? | Reasoning |
|-----------------|----------|-----------|
| Spoofing        | Yes | A workload whose OIDC `sub`/`aud` claims satisfy an overly-broad condition can spoof the identity the trust relationship intended to scope to (Track 1: any workflow in a trusted repo, not just the intended one; Track 2: any principal in a trusted AWS account, not just the intended role). |
| Tampering       | No (out of scope) | Requires compromising the OIDC token issuer itself (GitHub's or AWS's), not a misconfiguration this tool detects. |
| Repudiation      | Partial | Federated actions land in each cloud's own audit log (CloudTrail / Cloud Audit Logs) under the *assumed* identity, not the originating one — correlating the two requires this project's cross-cloud graph, which is itself a detective control this tool contributes. |
| Information Disclosure | Yes (consequence, not mechanism) | The actual harm of a successful escalation — reachable via the pathfinder's blast-radius reasoning, not analyzed as its own boundary here. |
| Denial of Service | No (out of scope, and explicitly forbidden — see `SCOPE.md` rule 3) | This tool never takes an action capable of causing it. |
| Elevation of Privilege | **Yes — this is the core finding class** | Both Track 1 and Track 2 are EoP: a principal that should only reach a moderate-privilege role in its home cloud reaches an admin/owner-equivalent identity in the *other* cloud because the trust condition under-scopes who it accepts. |

### TB2 — Credential-use boundary (the tool's own execution)

The boundary between the tool's own scanning credentials and the sandbox
accounts they read from. This is the boundary `SCOPE.md` rule 1 exists to
control.

| STRIDE          | Applies? | Mitigation |
|-----------------|----------|------------|
| Spoofing        | Low | Credentials are scoped to a purpose-built IAM identity per cloud (task 5); no shared/ambient credentials. |
| Tampering       | N/A | Read-only (`List*`/`Get*`, `cloudasset.viewer`-equivalent) — no write path exists to tamper with. |
| Repudiation      | Low | Each cloud's own audit trail (CloudTrail, Cloud Audit Logs) records every collector call under a distinctly-named identity, not a shared one. |
| Information Disclosure | **Primary risk here** | The collected graph contains real account IDs, ARNs, and project IDs. It must never leave the local working environment un-sanitized — this is what feeds TB3 below. |
| Denial of Service | Forbidden by design | `SCOPE.md` rule 3: no destructive action, ever, from any component including validation scripts. Read-only IAM scope enforces this at the permission layer, not just by convention. |
| Elevation of Privilege | **Structurally prevented** | The scanning identity itself must never be a viable escalation source — i.e. it must not appear as a `CAN_ASSUME`/`CAN_IMPERSONATE`/`FEDERATES_WITH` source in its own account's graph. Worth an explicit self-check once the rule engine exists (candidate addition to task 10 or the wrap-up validation pass in task 31). |

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
| Information Disclosure | **Primary risk here** | A raw graph export, an unredacted screenshot, or a copy-pasted ARN in a case-study writeup would identify the actual sandbox accounts. Every artifact that reaches `docs/` (case studies, diagrams, sample graph exports) must be sanitized to placeholder account IDs/ARNs/project IDs before being committed — this is a manual gate at tasks 22, 29, and 34, not an automated one, and should be treated as a checklist item at each of those tasks rather than assumed done. |
| Denial of Service | N/A | Not applicable to a static site. |
| Elevation of Privilege | N/A | Publishing findings doesn't grant anyone privilege; it *documents* a privilege path that has already been remediated (per the success criteria in `SCOPE.md`, remediation ships with the finding, so the published misconfiguration is a historical before/after, not a live one). |

---

## 3. The five cross-cloud escalation paths

Five structurally distinct escalation mechanisms, catalogued here regardless
of build status. Two are fully implemented (Track 1, Track 2); three are
deliberately deferred per `TASKS.md` but documented at full mechanism/
precondition/blast-radius detail so the catalog — and the reasoning for
what got cut — stands on its own.

Framework references use MITRE ATT&CK for Cloud (`attack.mitre.org`,
Cloud matrix) and NIST SP 800-53 / CIS Controls v8, as required by
`SCOPE.md`'s success criteria.

### Pattern 1 — CI/CD OIDC trust mismatch *(Track 1 — built)*

- **Mechanism:** A CI/CD workflow (GitHub Actions) is trusted by both an
  AWS IAM role (via an OIDC provider + role trust policy) and a GCP
  service account (via a Workload Identity Federation pool/provider). The
  AWS side is correctly scoped (control config); the GCP WIF provider's
  `attribute-condition` is planted with a loose match — trusting the
  issuer/subject pattern broadly rather than pinning the specific
  repo+branch+workflow the AWS side pins.
- **Precondition:** Any workflow able to satisfy the loose GCP-side
  condition (e.g. any workflow in the org, not just the intended repo) can
  mint a token impersonating the bound GCP service account.
- **Blast radius:** The GCP WIF provider is bound to a service account
  with `roles/owner` (task 17) — full project control from a workload that
  was only ever supposed to reach a moderate-privilege AWS role.
- **MITRE ATT&CK Cloud:** T1550.001 (Use Alternate Authentication Material
  — Application Access Token), via TA0004 (Privilege Escalation) through a
  trust-relationship abuse consistent with T1199 (Trusted Relationship).
- **NIST/CIS:** NIST SP 800-53 AC-3 (Access Enforcement) / CIS Control 5.4
  (restrict administrative privileges) and CIS Control 6.8 (define and
  maintain role-based access, applied to federated/non-human identities).
- **Status:** Built end-to-end (tasks 13–23), including the negative
  control (task 18).

### Pattern 2 — Overly-broad GCP WIF trust of an AWS principal *(Track 2 — built)*

- **Mechanism:** A GCP WIF pool/provider trusts AWS as an identity
  provider but scopes the trust only to the AWS account ID, omitting
  role-level scoping (no `attribute.aws_role` / equivalent condition
  narrowing which role ARN within that account is trusted).
- **Precondition:** *Any* IAM principal capable of assuming *any* role in
  the trusted AWS account can exchange that role's credentials for a GCP
  federated token — not just the specific role the binding was intended
  for.
- **Blast radius:** Bound to a second, high-privilege GCP service account
  (task 25) — effectively, every role in the AWS account becomes a path to
  that GCP privilege level, not just the one role that was supposed to
  have it.
- **MITRE ATT&CK Cloud:** T1199 (Trusted Relationship) combined with
  T1078.004 (Valid Accounts: Cloud Accounts) — the escalation doesn't
  require compromising a credential, only holding *any* sufficiently
  ordinary one in the trusted account.
- **NIST/CIS:** NIST SP 800-53 AC-6 (Least Privilege) — the missing
  role-ARN condition is a textbook least-privilege violation applied to a
  federation trust rather than a role policy. CIS Control 3.3 (configure
  data access control lists) as the general "scope trust to the minimum
  needed" analogue.
- **Status:** Built, reusing Track 1 infra (tasks 24–30), including a
  correctly role-scoped negative-control binding (task 28).

### Pattern 3 — Mirror-direction AWS-trusts-GCP *(deferred, documented only)*

- **Mechanism:** The inverse of Pattern 2 — an AWS IAM role's trust policy
  configures Google as a `Federated` OIDC principal
  (`accounts.google.com`) via `sts:AssumeRoleWithWebIdentity`, scoped only
  by issuer, without a `StringEquals`/`StringLike` condition narrowing the
  `sub` claim to a specific GCP service account.
- **Precondition:** Any GCP service account able to generate an
  `id_token` for that audience — which, absent the missing condition, is
  broader than intended — can assume the AWS role.
- **Blast radius:** Same shape as Pattern 2, mirrored: depends on the AWS
  role's granted permissions.
- **Why deferred:** Same underlying detection logic as Pattern 2 (missing
  subject-level scoping on a federation trust), just checked on the
  opposite trust direction. Building it would exercise the correlation
  engine's `FEDERATES_WITH` reverse-direction case but wouldn't add a new
  *class* of finding — judged low incremental value against the cost of a
  third fully-validated sandbox scenario. Detection logic in
  `analysis/escalation_rules.py` should still be written direction-agnostic
  where the cost is low, so this remains cheap to add later.
- **MITRE ATT&CK Cloud / NIST/CIS:** Same mappings as Pattern 2 (T1199 +
  T1078.004; NIST AC-6).

### Pattern 4 — Static credential leakage across the cloud boundary *(deferred, documented only)*

- **Mechanism:** A long-lived credential from one cloud (a GCP service
  account JSON key, an AWS access key pair) stored as a plaintext secret
  in the *other* cloud's secret store, CI variable, or object storage —
  bypassing federation's short-lived-token model entirely and creating a
  standing, non-expiring cross-cloud compromise path that this project's
  policy-graph traversal cannot see (it isn't an IAM relationship, it's a
  stored artifact).
- **Precondition:** Read access to wherever the key is stored (a bucket,
  a CI secret store, a config file committed to a repo).
- **Blast radius:** Full permission of whatever the leaked credential
  grants, with no expiry and no federation-side condition to narrow it.
- **Why deferred:** This is a genuinely different capability — content/
  secrets scanning (regex/entropy detection over storage and CI configs)
  rather than identity-graph traversal. Bolting it onto this project would
  blur its thesis (cross-cloud *policy* analysis) rather than sharpen it.
  Better suited to a dedicated follow-on tool.
- **MITRE ATT&CK Cloud:** T1552.001 (Unsecured Credentials: Credentials In
  Files) / T1528 (Steal Application Access Token) depending on the
  credential type.
- **NIST/CIS:** NIST SP 800-53 IA-5 (Authenticator Management — no
  long-lived secrets where a short-lived federated alternative exists);
  CIS Control 3.11 (encrypt sensitive data at rest) as the storage-side
  control this pattern violates.

### Pattern 5 — DR/failover identity & cross-cloud SSO deprovisioning gap *(deferred, documented only)*

- **Mechanism:** Two related sub-patterns grouped for scope reasons: (a) a
  disaster-recovery/failover identity provisioned with standing
  cross-cloud privilege "just in case," that sits unused and unreviewed
  between failover events; (b) an identity deprovisioned from a shared
  upstream IdP (e.g. removed from Okta/Azure AD) whose *downstream*
  federated bindings in AWS and GCP aren't cleaned up in lockstep, leaving
  a live trust relationship pointing at a subject that should no longer
  exist anywhere.
- **Precondition:** (a) requires no ongoing action — the exposure is the
  standing grant itself; (b) requires the deprovisioning event to have
  actually happened upstream while downstream federation config lagged.
- **Blast radius:** Whatever the DR identity or stale binding was scoped
  to — potentially very high, since DR identities are often provisioned
  broadly "to be safe."
- **Why deferred:** Both sub-patterns need a real, shared upstream IdP
  federated to *both* clouds and, for (b), a believable deprovisioning
  event to stage — meaningfully more sandbox setup (multi-region for (a),
  a third federated party for (b)) than the WIF/OIDC-only infra Tracks 1–2
  already require. Flagged for a future extension once that IdP
  infrastructure exists.
- **MITRE ATT&CK Cloud:** T1078.004 (Valid Accounts: Cloud Accounts) for
  both; T1098 (Account Manipulation) is the closest fit for the
  deprovisioning-lag case specifically.
- **NIST/CIS:** NIST SP 800-53 AC-2 (Account Management, esp. timely
  disablement) / CIS Control 5.3 (disable dormant accounts) for the DR
  identity; CIS Control 6.2 (establish an access revoking process) for
  the deprovisioning-lag case.

---

## 4. Correlation confidence tiers

The correlation engine (task 9) is what actually draws a `FEDERATES_WITH`
edge between an AWS-side trust statement and a GCP-side WIF binding (or the
mirror direction). Not every apparent match is equally trustworthy — a
naming coincidence is not the same evidence as a cryptographically
meaningful match — so every `FEDERATES_WITH` edge carries a confidence
tier that downstream severity scoring (`risk_weight`) and the rule engine
both key off of. This is what lets the tool prove a true negative (`SCOPE.md`
success criteria) rather than just pattern-matching on federation's mere
presence.

| Tier | Criteria | Example | Effect on scoring |
|------|----------|---------|--------------------|
| **HIGH** | Structural match: the AWS trust policy's `Federated` principal names the exact GCP WIF pool/provider resource path (or vice versa: the GCP `attribute-condition` pins the exact AWS role ARN), *and* any `sub`/audience condition is present and consistent on both sides. | AWS role trust policy federates to `accounts.google.com` with a `sub` condition matching one specific GCP service account's unique ID; that service account is the one bound to a WIF provider whose condition pins the corresponding AWS role ARN. | Edge is treated as a confirmed live escalation path if the target is high-privilege — this is the Track 1/Track 2 finding shape. Full `risk_weight` applied. |
| **MEDIUM** | Partial/structural match: the relationship is real and federation-based, but scoping is coarser than role/subject level on at least one side — e.g. account-ID-only trust with no role or subject condition. | The Track 2 misconfiguration itself: GCP WIF trusts an AWS account ID with no `attribute.aws_role` condition — the edge is real, but which specific AWS principal it resolves to is a *set*, not a single identity. | Still flagged, but the finding explicitly states the ambiguity ("any role in account X can traverse this edge") rather than naming one falsely-precise principal. This is itself the vulnerability signature for Pattern 2/3, so MEDIUM confidence in *precision* can still mean HIGH confidence in *risk*. |
| **LOW** | Heuristic/inferred: no structural linkage confirmed by either cloud's actual trust configuration — e.g. the same repo name, project name, or naming convention appears on both sides, suggesting a relationship a human likely intended, but nothing in either policy document actually encodes it. | A GCP service account named `gh-actions-deploy-sa` and an AWS role named `github-actions-deploy-role` exist in accounts known to belong to the same org, but neither has a federation binding to the other yet (or the binding uses a generic issuer with no distinguishing condition at all). | Surfaced only as an *advisory* note ("possible intended pairing, not a live trust relationship") — never treated as a `FEDERATES_WITH` edge the pathfinder traverses, and never contributes to a true-positive finding. Exists so the tool can flag naming-convention drift as a hygiene note without inflating the escalation-path count with guesses. |

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
- **Two clouds, two accounts, two use cases.** Findings generalize to the
  *pattern*, not to any specific organization's environment — this is a
  reference build against synthetic, self-planted misconfigurations, not
  a live audit of a real org's cross-cloud posture.
- **Azure is a documentation-only gap**, not a modeling gap — `graph_schema.py`
  and the escalation catalog above are cloud-agnostic by design, and
  `azure_collector.py` exists as a structurally complete stub specifically
  so wiring up a real Azure tenant later doesn't require touching the
  schema, correlation engine, or rule engine.
- **This threat model does not cover the analysis code's own supply
  chain** (dependency compromise of `boto3`, `google-cloud-asset`, etc.) —
  standard dependency-hygiene practice applies and isn't specific enough
  to this project's thesis to warrant its own trust boundary here.
