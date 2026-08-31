# Threat Model — STRIDE Analysis

Three trust boundaries apply to this project — one is the subject of the
analysis (the cloud API boundary crossed by federation), and two are trust
boundaries of the tool itself.

## TB1 — Cloud API boundary (the object of study)

The boundary between an identity's home cloud and the cloud it federates
into: a GitHub Actions runner's OIDC token crossing into AWS via
`sts:AssumeRoleWithWebIdentity`, a workload's federated token crossing into
GCP via a Workload Identity Federation pool, or a GCP service account's
identity token crossing into AWS the same way. This is not a boundary the
tool defends — it's the boundary the tool exists to map and evaluate,
because it's evaluated correctly by neither side's native tooling in
isolation.

| STRIDE | Applies? | Reasoning |
|---|---|---|
| Spoofing | Yes | A workload whose OIDC `sub`/`aud` claims satisfy an overly-broad condition can spoof the identity the trust relationship intended to scope to. |
| Tampering | No (out of scope) | Requires compromising the OIDC token issuer itself, not a misconfiguration this tool detects. |
| Repudiation | Partial | Federated actions land in each cloud's own audit log under the *assumed* identity, not the originating one — correlating the two requires this project's cross-cloud graph. |
| Information Disclosure | Yes (consequence, not mechanism) | The actual harm of a successful escalation — reachable via the pathfinder's blast-radius reasoning. |
| Denial of Service | No (out of scope, and explicitly forbidden) | This tool never takes an action capable of causing it. |
| Elevation of Privilege | **Yes — this is the core finding class** | All three tracks are EoP: a principal that should only reach a moderate-privilege identity in its home cloud reaches an admin/owner-equivalent identity in the other cloud because the trust condition under-scopes who it accepts. |

## TB2 — Credential-use boundary (the tool's own execution)

The boundary between the tool's own scanning credentials and the sandbox
accounts they read from.

| STRIDE | Applies? | Mitigation |
|---|---|---|
| Spoofing | Low | Credentials are scoped to a purpose-built IAM identity per cloud; no shared/ambient credentials, and impersonation only — no downloaded service account key on the GCP side. |
| Tampering | N/A | Read-only — no write path exists to tamper with. |
| Repudiation | Low | Each cloud's own audit trail records every collector call under a distinctly-named identity, not a shared one. |
| Information Disclosure | **Primary risk here** | The collected graph contains real account IDs, ARNs, and project IDs. It must never leave the local working environment un-sanitized. |
| Denial of Service | Forbidden by design | No destructive action, ever, from any component. Read-only IAM scope enforces this at the permission layer, not just by convention. |
| Elevation of Privilege | **Structurally prevented** | The scanning identity itself must never be a viable escalation source — it must not appear as a `CAN_ASSUME`/`CAN_IMPERSONATE`/`FEDERATES_WITH` source in its own account's graph. |

## TB3 — Publication boundary (repo + portfolio site)

The boundary between raw findings (real sandbox account IDs, ARNs, project
IDs, screenshots) and anything committed to this repo or published to the
public site.

| STRIDE | Applies? | Mitigation |
|---|---|---|
| Spoofing | N/A | Not applicable to static published content. |
| Tampering | Low | Standard repo/branch-protection hygiene; not a novel risk this project introduces. |
| Repudiation | N/A | Not applicable. |
| Information Disclosure | **Primary risk here** | A raw graph export, an unredacted screenshot, or a copy-pasted ARN in a case-study writeup would identify the actual sandbox accounts. `src/sanitize.py` closes most of this automatically — but every artifact that reaches the public site should still be treated as a checklist item, not assumed sanitized. |
| Denial of Service | N/A | Not applicable to a static site. |
| Elevation of Privilege | N/A | Publishing findings doesn't grant anyone privilege; it documents a privilege path that has already been remediated. |
