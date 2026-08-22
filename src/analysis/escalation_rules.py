"""
escalation_rules.py -- task 10

Encodes the 5-pattern cross-cloud escalation catalog from
docs/THREAT_MODEL.md #3 as graph-pattern checks against a correlated graph
(the output of correlation.correlate()).

Build status mirrors TASKS.md / SCOPE.md exactly -- this module does not
pretend otherwise:

  Pattern 1 (CI/CD OIDC mismatch)              IMPLEMENTED  -- Track 1
  Pattern 2 (overly-broad GCP WIF/AWS trust)   IMPLEMENTED  -- Track 2 shape
                                                (validated once Track 2
                                                 sandbox infra exists,
                                                 TASKS.md task 27/28)
  Pattern 3 (mirror AWS-trusts-GCP)            DEFERRED (documented only)
  Pattern 4 (static credential leakage)        DEFERRED (documented only,
                                                genuinely different
                                                capability -- secrets
                                                scanning, not graph
                                                traversal)
  Pattern 5 (DR/failover + deprovisioning gap) DEFERRED (documented only,
                                                needs a shared upstream
                                                IdP this project doesn't
                                                have sandbox infra for)

`run_all()` only executes rules marked IMPLEMENTED and reports which
patterns were skipped and why -- it never raises for a deferred pattern,
matching the collector-stub convention already used elsewhere in this repo
(azure_collector.py, gcp_collector.py) rather than a NotImplementedError
that would break the pipeline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

from ..graph_schema import Cloud, Edge, EdgeType, Node
from .confidence import Confidence

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"  # reaches an is_admin=True node
    HIGH = "high"          # reaches a privileged-but-not-admin node
    INFO = "info"          # federation edge exists, no privileged target


class RuleStatus(str, Enum):
    IMPLEMENTED = "implemented"
    DEFERRED = "deferred"


@dataclass
class Finding:
    pattern_id: int
    pattern_name: str
    severity: Severity
    confidence: Confidence
    source_node: str
    bridge_node: str | None
    target_node: str
    evidence: str
    mitre_attack: str
    nist_cis: str


@dataclass
class RuleResult:
    findings: list[Finding] = field(default_factory=list)
    skipped_patterns: list[tuple[int, str, str]] = field(default_factory=list)  # (id, name, reason)


# ---------------------------------------------------------------------------
# Pattern 1 -- CI/CD OIDC trust mismatch (Track 1)
# ---------------------------------------------------------------------------


def check_pattern1_cicd_oidc_mismatch(nodes: dict[str, Node], edges: list[Edge]) -> list[Finding]:
    """
    Shape: a CROSS_CLOUD bridge node (a third-party OIDC issuer, post
    correlation.merge_oidc_bridges) with FEDERATES_WITH edges reaching into
    BOTH an AWS node and a GCP node -- confirming it's a genuine
    multi-cloud bridge, not just one cloud's edge in isolation. Any such
    edge whose target is privileged is a finding; confidence (HIGH/MEDIUM,
    LOW is already filtered out by correlation.tag_confidence) sets
    severity nuance but not whether it's reported -- an under-scoped bridge
    reaching admin is CRITICAL regardless of precision.
    """
    findings: list[Finding] = []

    bridges = [n for n in nodes.values() if n.cloud == Cloud.CROSS_CLOUD]
    for bridge in bridges:
        outbound = [e for e in edges if e.source == bridge.id and e.type == EdgeType.FEDERATES_WITH]
        clouds_reached = {nodes[e.target].cloud for e in outbound if e.target in nodes}
        if not ({Cloud.AWS, Cloud.GCP} <= clouds_reached):
            continue  # not actually used as a bridge by both clouds

        for e in outbound:
            target = nodes.get(e.target)
            if not target or not target.is_admin:
                continue
            confidence = Confidence(e.attributes.get("confidence", Confidence.MEDIUM.value))
            findings.append(
                Finding(
                    pattern_id=1,
                    pattern_name="CI/CD OIDC trust mismatch",
                    severity=Severity.CRITICAL,
                    confidence=confidence,
                    source_node=bridge.id,
                    bridge_node=bridge.id,
                    target_node=target.id,
                    evidence=(
                        f"{bridge.name} federates into both AWS and {target.cloud.value.upper()}; "
                        f"the edge into {target.name} ({target.cloud.value}) resolves with "
                        f"{confidence.value.upper()} confidence and reaches an admin-equivalent identity. "
                        + (e.evidence or "")
                    ),
                    mitre_attack="T1550.001 (Use Alternate Authentication Material) / T1199 (Trusted Relationship)",
                    nist_cis="NIST SP 800-53 AC-3 / CIS Control 5.4, 6.8",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Pattern 2 -- overly-broad GCP WIF trust of an AWS principal (Track 2)
# ---------------------------------------------------------------------------


def check_pattern2_gcp_wif_overbroad_aws_trust(nodes: dict[str, Node], edges: list[Edge]) -> list[Finding]:
    """
    Shape: a DIRECT FEDERATES_WITH edge (no third-party bridge node) from an
    AWS-cloud-typed source into a GCP target, where correlation.py's
    merge_direct_references() resolved (or failed to fully resolve) the
    trust down to less than a specific role ARN -- i.e. a MEDIUM-confidence
    direct edge. Implemented now per task 9/10's general scope; end-to-end
    validation against real Track 2 sandbox data is TASKS.md tasks 27-28,
    since that infra doesn't exist yet (see terraform/track1/README.md --
    Track 2 reuses Track 1's infra once built).
    """
    findings: list[Finding] = []

    for e in edges:
        if e.type != EdgeType.FEDERATES_WITH:
            continue
        source = nodes.get(e.source)
        target = nodes.get(e.target)
        if not source or not target:
            continue
        # Direct cross-cloud edge: no third-party bridge in between, source
        # and target sit in two different single clouds (not CROSS_CLOUD).
        if source.cloud not in (Cloud.AWS, Cloud.GCP) or target.cloud not in (Cloud.AWS, Cloud.GCP):
            continue
        if source.cloud == target.cloud:
            continue
        if not target.is_admin:
            continue
        confidence = Confidence(e.attributes.get("confidence", Confidence.MEDIUM.value))
        if confidence != Confidence.MEDIUM:
            continue  # HIGH-confidence direct edges are correctly-scoped controls, not findings

        findings.append(
            Finding(
                pattern_id=2,
                pattern_name="Overly-broad GCP WIF trust of an AWS principal",
                severity=Severity.CRITICAL,
                confidence=confidence,
                source_node=source.id,
                bridge_node=None,
                target_node=target.id,
                evidence=(
                    f"{source.name} ({source.cloud.value}) federates directly into "
                    f"{target.name} ({target.cloud.value}) with only account/org-level "
                    "scoping -- any principal in the trusted account can traverse this edge. "
                    + (e.evidence or "")
                ),
                mitre_attack="T1199 (Trusted Relationship) / T1078.004 (Valid Accounts: Cloud Accounts)",
                nist_cis="NIST SP 800-53 AC-6 / CIS Control 3.3",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Deferred patterns (documented only -- see docs/THREAT_MODEL.md #3)
# ---------------------------------------------------------------------------

DEFERRED_PATTERNS = [
    (3, "Mirror-direction AWS-trusts-GCP", "Same detection logic as Pattern 2, opposite trust direction -- low incremental value as a 3rd case (SCOPE.md)."),
    (4, "Static credential leakage across the cloud boundary", "Genuinely different capability (secrets/content scanning, not policy-graph traversal) -- future extension."),
    (5, "DR/failover identity + cross-cloud SSO deprovisioning gap", "Needs a shared upstream IdP federated to both clouds -- no sandbox infra for this exists."),
]


RULES = [
    (1, "CI/CD OIDC trust mismatch", RuleStatus.IMPLEMENTED, check_pattern1_cicd_oidc_mismatch),
    (2, "Overly-broad GCP WIF trust of an AWS principal", RuleStatus.IMPLEMENTED, check_pattern2_gcp_wif_overbroad_aws_trust),
]


def run_all(nodes: list[Node], edges: list[Edge]) -> RuleResult:
    """Run every IMPLEMENTED rule against a correlated graph; record skips for deferred ones."""
    node_map = {n.id: n for n in nodes}
    result = RuleResult()

    for pattern_id, name, status, fn in RULES:
        if status is not RuleStatus.IMPLEMENTED:
            continue
        found = fn(node_map, edges)
        logger.info("Pattern %d (%s): %d finding(s)", pattern_id, name, len(found))
        result.findings.extend(found)

    for pattern_id, name, reason in DEFERRED_PATTERNS:
        result.skipped_patterns.append((pattern_id, name, reason))

    return result
