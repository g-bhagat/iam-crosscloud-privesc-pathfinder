"""
confidence.py

Executable form of the 3-tier FEDERATES_WITH confidence model documented
in docs/THREAT_MODEL.md #4. Shared by correlation.py (which assigns a tier
to every cross-cloud edge it resolves) and escalation_rules.py (which
decides what to do with each tier).

The tier answers one question: *how precisely does this edge's own trust
condition resolve to a single expected principal?* It is deliberately
independent of how privileged the edge's target is -- that combination is
what escalation_rules.py reasons about.

    HIGH    exact single subject pinned (repo+branch, or a specific ARN/
            resource path) -- the tool is confident about *who* can
            traverse this edge.
    MEDIUM  real federation, but scoping stops at a coarser boundary
            (org-only, account-only) -- the tool knows the edge is live
            but the resolvable principal is a *set*, not one identity.
            This is precisely the Track 1 / Track 2 misconfiguration
            signature: MEDIUM precision can still mean HIGH risk.
    LOW     no structural evidence beyond a naming coincidence -- never
            promoted into pathfinder traversal, surfaced only as an
            advisory hygiene note.
"""

from __future__ import annotations

import json
import re
from enum import Enum


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# risk_weight assigned per tier, per graph_schema.py's contract: lower =
# easier/likelier to exploit = cheaper pathfinder traversal cost. A tightly
# scoped (HIGH-confidence) edge is the *harder* one to abuse -- only the one
# pinned principal can use it -- so it gets a higher (costlier) weight than
# a loosely scoped (MEDIUM-confidence) edge that many principals can use.
RISK_WEIGHT_BY_CONFIDENCE = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.4,
    # LOW-confidence edges are never added to the traversal graph at all
    # (see escalation_rules.py / pathfinder.py), so no risk_weight is
    # meaningful for them -- this entry exists only so callers that do
    # look it up fail loudly instead of KeyError.
    Confidence.LOW: None,
}


def score_aws_condition(condition_json: str | None) -> Confidence:
    """
    Score an AWS trust-policy Condition block (as the JSON string
    AWSCollector stores on an Edge.condition, e.g. from
    `json.dumps(stmt.get("Condition"))`).

    HIGH:   StringEquals/StringLike on the OIDC `sub` claim naming a
            specific repo AND ref (`repo:org/repo:ref:refs/heads/x`), or
            any condition that otherwise pins a single external ID /
            role session name. Also HIGH: a Google OIDC federation
            condition's `<issuer>:sub` claim (e.g.
            `accounts.google.com:sub`) pinned to Google's numeric
            subject ID for one specific principal -- the Track 3
            (AWS-trusts-GCP) equivalent of a GitHub `sub` pin. Google's
            subject IDs are long (~21-digit) numeric strings with no
            further delimited structure, unlike GitHub's `repo:org/...`
            shape, so there's nothing to pattern-match beyond "long
            enough to be one, sitting under the right key" -- 15+ digits
            keeps it clearly distinguishable from a 12-digit AWS account
            ID (the check right above) and is well under any real
            Google subject ID's actual length. The `*:sub` key
            requirement is load-bearing: a long number under some other,
            unrelated condition key is deliberately NOT treated as a
            pin on its own.
    MEDIUM: a condition is present but only narrows to a coarser scope
            (e.g. `repo:org/*` with no ref, or an account/org-level
            match without a specific subject).
    LOW:    no condition at all -- an unconditioned Federated/AWS
            principal trust (this is also generally caught upstream as
            `external_facing=True` on the role, but confidence-wise it's
            LOW: there's no subject pinning to reason about at all).
    """
    if not condition_json:
        return Confidence.LOW

    try:
        condition = json.loads(condition_json)
    except (TypeError, json.JSONDecodeError):
        return Confidence.LOW

    items = _flatten_condition_items(condition)
    if not items:
        return Confidence.LOW

    for key, v in items:
        # repo:org/repo:ref:refs/heads/branch -- both repo AND ref pinned
        if re.match(r"^repo:[^/]+/[^:]+:ref:refs/", v):
            return Confidence.HIGH
        # a specific role ARN, account ID + fixed external ID, etc.
        if re.match(r"^arn:aws:", v) or re.match(r"^[0-9]{12}$", v):
            return Confidence.HIGH
        # Google OIDC subject ID pin, e.g. "accounts.google.com:sub": "1122...".
        if key.endswith(":sub") and re.match(r"^\d{15,}$", v):
            return Confidence.HIGH

    for _key, v in items:
        # repo:org/repo:* (repo pinned, ref wildcarded) or repo:org/*
        # (org pinned only) -- real narrowing, but to a set, not one ID.
        if v.startswith("repo:"):
            return Confidence.MEDIUM

    return Confidence.MEDIUM


def score_gcp_condition(attribute_condition: str | None, aws_account_id: str | None = None) -> Confidence:
    """
    Score a GCP Workload Identity Federation provider's CEL
    `attribute_condition` string.

    aws_account_id: the WIF provider's own --account-id, when known (see
        gcp_collector.py's AWS-type-provider branch, which stores this on
        the edge as attributes["aws_account_id"] -- correlation.py's
        _score_edge passes it through). An AWS-type WIF provider is
        ALWAYS scoped to exactly one AWS account at the provider level --
        that field is mandatory when creating one -- so "no
        attribute_condition at all" for this kind of provider still
        means real narrowing to one account, just expressed structurally
        rather than in the CEL condition string. Passing this floors an
        otherwise-LOW result to MEDIUM; it never lowers a HIGH result,
        and it's meaningless for a GitHub-shaped provider (omit it there
        -- for that shape, no condition genuinely means no scoping at
        all).

    HIGH:   checks `assertion.repository ==` (and ideally `assertion.ref
            ==`) -- pinned to one repo (+ branch). Also HIGH: an AWS
            role pinned by ARN -- `assertion.arn ==` / `assertion.role
            ==` (exact match), or the standard
            `assertion.arn.startsWith('arn:aws:sts::<account>:assumed-
            role/<role-name>/')` idiom (Google's own recommended shape
            for this, since an STS assumed-role ARN's session-name
            suffix is dynamic and can never be pinned with `==`) --
            Track 2's negative-control shape.
    MEDIUM: checks only `assertion.repository_owner ==` (org-level); an
            AWS account-ID-only match (`assertion.account ==`), or an
            `assertion.arn.startsWith(...)` prefix that stops at the
            account/assumed-role boundary with no role name after it --
            both are Track 2's actual planted-misconfiguration shape,
            real narrowing but to every principal in one account, not
            one role; or `aws_account_id` is known and the condition
            itself is empty or doesn't match any recognized shape (see
            above -- real narrowing expressed at the provider level).
    LOW:    empty/missing condition with no aws_account_id context, or a
            condition that doesn't constrain the subject at all (e.g.
            only checks `aud`).
    """
    cond = attribute_condition or ""

    has_ref = bool(re.search(r"assertion\.ref\s*==", cond))
    has_repo = bool(re.search(r"assertion\.repository\s*==", cond))
    has_repo_owner_only = bool(re.search(r"assertion\.repository_owner\s*==", cond)) and not has_repo

    arn_exact_match = bool(re.search(r"assertion\.(arn|role)\s*==", cond))
    # The standard idiom for pinning an STS assumed-role ARN: the
    # session-name suffix is dynamic per-assumption, so `==` can never
    # match one -- startsWith() up to and including a specific role name
    # is as precise as this shape gets. A prefix that stops before/at
    # "assumed-role/" itself (nothing after it) only narrows to the
    # account, not a specific role.
    starts_with_match = re.search(r"assertion\.arn\.startsWith\(\s*['\"]([^'\"]+)['\"]\s*\)", cond)
    role_pinned_prefix = bool(starts_with_match and re.search(r"assumed-role/[^/]+/?$", starts_with_match.group(1)))
    account_only_prefix = bool(starts_with_match) and not role_pinned_prefix

    # Track 2 shape: GCP trusting an AWS principal directly, scoped only
    # to account ID with no role-level condition.
    has_aws_account_only = (
        bool(re.search(r"assertion\.account\s*==", cond)) and not arn_exact_match and not role_pinned_prefix
    )

    if has_repo and has_ref:
        return Confidence.HIGH
    if arn_exact_match or role_pinned_prefix:
        return Confidence.HIGH
    if has_repo or has_repo_owner_only or has_aws_account_only or account_only_prefix:
        return Confidence.MEDIUM
    if aws_account_id:
        # No CEL condition (or nothing this function recognizes), but the
        # provider itself is scoped to one AWS account -- real
        # structural narrowing, not "no evidence of scoping at all".
        return Confidence.MEDIUM

    return Confidence.LOW


def _flatten_condition_items(condition: dict) -> list[tuple[str, str]]:
    """AWS Condition blocks nest as {operator: {key: value_or_list}}.
    Keeps each value's condition key too -- needed to recognize a value
    that's only a HIGH-confidence pin when paired with a specific key
    shape (a Google OIDC subject ID is "just a long number"; it only
    means "this condition names one specific identity" when it's under a
    `*:sub` key, not some unrelated numeric condition)."""
    items: list[tuple[str, str]] = []
    if not isinstance(condition, dict):
        return items
    for operator_block in condition.values():
        if not isinstance(operator_block, dict):
            continue
        for key, v in operator_block.items():
            if isinstance(v, list):
                items.extend((key, str(x)) for x in v)
            else:
                items.append((key, str(v)))
    return items
