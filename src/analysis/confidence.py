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
            role session name.
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

    values = _flatten_condition_values(condition)
    if not values:
        return Confidence.LOW

    for v in values:
        # repo:org/repo:ref:refs/heads/branch -- both repo AND ref pinned
        if re.match(r"^repo:[^/]+/[^:]+:ref:refs/", v):
            return Confidence.HIGH
        # a specific role ARN, account ID + fixed external ID, etc.
        if re.match(r"^arn:aws:", v) or re.match(r"^[0-9]{12}$", v):
            return Confidence.HIGH

    for v in values:
        # repo:org/repo:* (repo pinned, ref wildcarded) or repo:org/*
        # (org pinned only) -- real narrowing, but to a set, not one ID.
        if v.startswith("repo:"):
            return Confidence.MEDIUM

    return Confidence.MEDIUM


def score_gcp_condition(attribute_condition: str | None) -> Confidence:
    """
    Score a GCP Workload Identity Federation provider's CEL
    `attribute_condition` string.

    HIGH:   checks `assertion.repository ==` (and ideally `assertion.ref
            ==`) -- pinned to one repo (+ branch).
    MEDIUM: checks only `assertion.repository_owner ==` (org-level) or
            an AWS account-ID-only match with no role ARN condition --
            this is the Track 1 / Track 2 planted-misconfiguration shape.
    LOW:    empty/missing condition, or a condition that doesn't
            constrain the subject at all (e.g. only checks `aud`).
    """
    if not attribute_condition or not attribute_condition.strip():
        return Confidence.LOW

    cond = attribute_condition

    has_ref = bool(re.search(r"assertion\.ref\s*==", cond))
    has_repo = bool(re.search(r"assertion\.repository\s*==", cond))
    has_repo_owner_only = bool(re.search(r"assertion\.repository_owner\s*==", cond)) and not has_repo
    # Track 2 shape: GCP trusting an AWS principal directly, scoped only
    # to account ID with no role-ARN-level condition.
    has_aws_account_only = bool(re.search(r"assertion\.account\s*==", cond)) and not re.search(
        r"assertion\.(arn|role)\s*==", cond
    )

    if has_repo and has_ref:
        return Confidence.HIGH
    if re.search(r"assertion\.(arn|role)\s*==", cond):
        return Confidence.HIGH
    if has_repo or has_repo_owner_only or has_aws_account_only:
        return Confidence.MEDIUM

    return Confidence.LOW


def _flatten_condition_values(condition: dict) -> list[str]:
    """AWS Condition blocks nest as {operator: {key: value_or_list}}."""
    values: list[str] = []
    if not isinstance(condition, dict):
        return values
    for operator_block in condition.values():
        if not isinstance(operator_block, dict):
            continue
        for v in operator_block.values():
            if isinstance(v, list):
                values.extend(str(x) for x in v)
            else:
                values.append(str(v))
    return values
