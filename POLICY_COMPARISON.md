# Policy Comparison — the three vulnerabilities, in plain terms

This document exists for one reason: a reviewer shouldn't have to read
Terraform to understand what this project found. Each track below shows
the exact vulnerable policy text, the exact fixed version, and why the
difference matters — no HCL knowledge required.

Full infrastructure-as-code lives in `terraform/track1/`, `track2/`,
`track3/`. Full technical rationale lives in `docs/THREAT_MODEL.md`.
This document is the fast path between those two.

---

## Track 1 — CI/CD identity trusted by both clouds, scoped correctly on
## one side, not the other

**One sentence:** A GitHub Actions identity is trusted by both AWS and
GCP. AWS scoped that trust correctly. GCP didn't — checking only "some
repo in this org," not the specific repo. Any repo under the same
GitHub account, not just the intended one, can become GCP project owner.

**The vulnerable condition (GCP WIF provider):**
```
assertion.repository_owner == "g-bhagat"
```
Confirms the token came from *some* repository owned by this account.
Nothing more.

**The fixed condition:**
```
assertion.repository == "g-bhagat/iam-crosscloud-victim-pipeline" &&
assertion.ref == "refs/heads/main"
```
Confirms the token came from *this exact* repository, on *this exact*
branch.

**The diff is one missing clause** — checking the specific repository
and branch instead of just the account. That single omission is the
entire vulnerability.

**Blast radius:** Full GCP project ownership (`roles/owner`), reachable
from any repository an attacker could create or compromise under the
same GitHub account — not limited to the intended CI/CD repo.

**Real, validated:** Real AWS + GCP infrastructure, real Terraform,
real detection run — confirmed true positive on the loose provider,
true negative on the scoped one, in the same scan.

**Framework mapping:** MITRE ATT&CK T1550.001 (Use Alternate
Authentication Material) / T1199 (Trusted Relationship). NIST SP
800-53 AC-3. CIS Controls 5.4, 6.8.

---

## Track 2 — GCP trusting an AWS account directly, without a third party

**One sentence:** GCP was configured to trust *any* identity in a
specific AWS account, with no restriction on which specific role or
user within that account. Every IAM identity in that AWS account —
not just the one CI/CD role it was meant for — can become a GCP
service account with full project ownership.

**The vulnerable condition (GCP WIF provider, AWS-type):**
No `attribute_condition` at all. The provider's `account_id` restriction
is real — only this one AWS account can use it — but that's the entire
restriction. Nothing narrows it further.

**The fixed condition:**
```
assertion.arn.startsWith('arn:aws:sts::<account-id>:assumed-role/track2-test-role/')
```
Pins the trust to one specific IAM role within that account, not the
account as a whole.

**The diff is the presence or absence of a role-level condition** —
account-level trust alone is not the same as role-level trust, even
though it looks similarly "scoped" at a glance.

**Blast radius:** Full GCP project ownership, reachable from *any*
IAM identity in the trusted AWS account — including identities that
have nothing to do with the intended integration.

**Real, validated:** Real Workload Identity Federation exchange proven
live — a genuine AWS session token was exchanged for a real GCP access
token through the loose provider. Detection confirmed true positive on
the loose binding, true negative on the role-scoped one.

**Framework mapping:** MITRE ATT&CK T1199 (Trusted Relationship) /
T1078.004 (Valid Accounts: Cloud Accounts). NIST SP 800-53 AC-6. CIS
Control 3.3.

---

## Track 3 — AWS trusting GCP directly, the mirror direction

**One sentence:** AWS was configured to accept any Google-issued identity
token, with no restriction on *which* Google Cloud identity sent it. Any
GCP service account in the project — including ones with no notable
permissions of their own — can become an AWS administrator.

**The vulnerable condition (AWS role trust policy):**
```
"accounts.google.com:oaud": "sts.amazonaws.com"
```
Confirms the token was meant for AWS. Doesn't confirm *which* Google
identity sent it.

**The fixed condition:**
```
"accounts.google.com:oaud": "sts.amazonaws.com",
"accounts.google.com:sub": "<specific service account's unique ID>"
```
Adds a second check pinning the token to one specific GCP service
account.

**The diff is a missing subject-pinning clause** — same shape of gap
as Track 1 and Track 2, this time on AWS's side of the relationship.

**Blast radius:** Full AWS `AdministratorAccess`, reachable from any
GCP service account capable of generating a Google-signed identity
token — a completely ordinary-looking GCP identity with no other
notable permissions becomes AWS admin.

**Real, validated:** A real Google-signed identity token was generated
and successfully exchanged for temporary AWS admin credentials via
`AssumeRoleWithWebIdentity` — a genuine, live exploit, not a
theoretical config review. Detection confirmed true positive/negative.

**Framework mapping:** MITRE ATT&CK T1199 (Trusted Relationship) /
T1078.004 (Valid Accounts: Cloud Accounts). NIST SP 800-53 AC-6. CIS
Control 3.3.

---

## The pattern across all three

Every vulnerability here has the same shape: **a trust relationship
that authenticates correctly, but authorizes too broadly** — confirming
"this request is genuinely from the expected identity provider," without
confirming "this request is from the *specific* identity it should be."
The fix, every time, is the same kind of change: add the missing clause
that narrows *who*, not just *whether*.

The direction differs — GCP trusting a third party (Track 1), GCP
trusting AWS directly (Track 2), AWS trusting GCP directly (Track 3) —
but the underlying mistake, and the underlying fix, generalizes across
all of them. That generalization is the actual finding worth taking
away from this project, beyond the three individual misconfigurations.
