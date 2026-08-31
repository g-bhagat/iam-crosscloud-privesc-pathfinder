# Threat Model — STRIDE Analysis

Three trust boundaries apply to this project — one is the subject of the
analysis (the cloud API boundary crossed by federation), and two are trust
boundaries of the tool itself. Only the STRIDE categories that are genuinely
applicable and exploitable at each boundary are listed below.

## Trust Boundary 1 — Cloud API boundary

The boundary between an identity's home cloud and the cloud it federates
into: a GitHub Actions runner's OIDC token crossing into AWS via
`sts:AssumeRoleWithWebIdentity`, a workload's federated token crossing into
GCP via a Workload Identity Federation pool, or a GCP service account's
identity token crossing into AWS the same way. This is not a boundary the
tool defends — it's the boundary the tool exists to map and evaluate,
because it's evaluated correctly by neither side's native tooling in
isolation.

| STRIDE | Notes |
|---|---|
| Spoofing | A workload whose OIDC `sub`/`aud` claims satisfy an overly-broad condition can spoof the identity the trust relationship intended to scope to. |
| Information Disclosure | The actual harm of a successful escalation — reachable via the pathfinder's blast-radius reasoning. |
| Elevation of Privilege | A principal that should only reach a moderate-privilege identity in its home cloud instead reaches an admin- or owner-equivalent identity in the other cloud, because the trust condition under-scopes who it accepts. |

## Trust Boundary 2 — Credential-use boundary

The boundary between the tool's own scanning credentials and the sandbox
accounts they read from.

| STRIDE | Notes |
|---|---|
| Information Disclosure | The collected graph contains real account IDs, ARNs, and project IDs. It must never leave the local working environment un-sanitized. |

## Trust Boundary 3 — Publication boundary

The boundary between raw findings (real sandbox account IDs, ARNs, project
IDs, screenshots) and anything committed to this repo or published to the
public site.

| STRIDE | Notes |
|---|---|
| Information Disclosure | A raw graph export, an unredacted screenshot, or a copy-pasted ARN in a case-study writeup would identify the actual sandbox accounts. `src/sanitize.py` closes most of this automatically — but every artifact that reaches the public site should still be treated as a checklist item, not assumed sanitized. |
