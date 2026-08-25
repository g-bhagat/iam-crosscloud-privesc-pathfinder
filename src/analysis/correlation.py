"""
correlation.py -- task 9

The cross-cloud correlation engine. AWSCollector and GCPCollector each emit
FEDERATES_WITH edges independently, from whatever their own cloud's trust
configuration says -- they have no visibility into the other cloud. This
module is what actually connects the two collected graphs into one walkable
identity graph, and tags every resulting cross-cloud edge with a confidence
tier (see confidence.py / docs/THREAT_MODEL.md #4).

Two structurally different bridging shapes, both handled here:

1. Third-party bridge (Pattern 1 / Track 1 shape): AWS and GCP each trust
   the *same external* OIDC issuer (e.g. GitHub Actions) independently --
   neither cloud references the other directly. AWSCollector emits a node
   for the OIDC provider ARN it sees in a role's trust policy; a GCPCollector
   (task 8, still a stub) is expected to emit a node for the WIF provider's
   issuer_uri, per the node/edge contract documented in gcp_collector.py.
   Both nodes name the *same* issuer host under different surface forms
   (an ARN vs. a bare issuer URL) -- `merge_oidc_bridges` normalizes both
   to a bare host and merges them into one canonical node, which is what
   makes AWS role <-> GCP service account actually reachable in one walk.

2. Direct reference (Pattern 2/3 shape): one cloud's trust condition
   embeds a literal reference to a resource that exists as a node in the
   *other* cloud's collected graph (a GCP WIF `attribute_condition`
   naming a specific AWS role ARN, or an AWS trust policy's `Federated`
   principal naming a GCP WIF provider resource path). No shared
   third-party node is involved -- `merge_direct_references` rewrites the
   edge's endpoint straight to the matching node, if one is found.
   Not exercised by Track 1 data (no Track 2 sandbox infra exists yet),
   but built generically now per task 9's scope; see
   tests/test_correlation.py::test_direct_reference_merge for a synthetic
   Track-2-shaped exercise of this path.

Confidence + risk_weight tagging happens after merging, per edge, using
confidence.py's scoring functions -- so it stays correct regardless of
which merge shape produced the connection.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, replace

from ..graph_schema import Cloud, Edge, EdgeType, Node
from .confidence import (
    RISK_WEIGHT_BY_CONFIDENCE,
    Confidence,
    score_aws_condition,
    score_gcp_condition,
)

logger = logging.getLogger(__name__)

# Node id/attribute keys GCPCollector (task 8) is expected to use for WIF
# bridge nodes -- see the design note this module's docstring points at in
# gcp_collector.py. Kept here as a single source of truth so correlation
# logic and the eventual collector implementation don't drift apart.
GCP_WIF_BRIDGE_PREFIX = "gcp:wif_bridge:"


@dataclass
class AdvisoryNote:
    """
    A LOW-confidence hint the correlation engine found but deliberately did
    NOT wire into the traversal graph -- e.g. a GCP SA and an AWS role that
    look like they were meant to pair up (naming convention) but have no
    structural federation evidence linking them. Surfaced separately so the
    tool can flag naming-convention drift as a hygiene note without
    inflating the escalation-path count with guesses (docs/THREAT_MODEL.md #4).
    """

    node_a: str
    node_b: str
    reason: str


def _oidc_host(identifier: str) -> str | None:
    """
    Normalize an OIDC issuer reference to a bare host for cross-cloud
    matching, e.g.:
      "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        -> "token.actions.githubusercontent.com"
      "https://token.actions.githubusercontent.com" -> "token.actions.githubusercontent.com"
    """
    if not identifier:
        return None
    # AWS OIDC provider ARN: strip everything up through "oidc-provider/".
    m = re.search(r"oidc-provider/(.+)$", identifier)
    if m:
        identifier = m.group(1)
    return identifier.removeprefix("https://").removeprefix("http://").rstrip("/").lower() or None


def merge_oidc_bridges(nodes: dict[str, Node], edges: list[Edge]) -> tuple[dict[str, Node], list[Edge]]:
    """
    Merge AWS-side and GCP-side third-party OIDC bridge nodes that
    reference the same issuer host into one canonical CROSS_CLOUD node.
    Mutates neither input; returns new (nodes, edges).
    """
    nodes = dict(nodes)
    edges = list(edges)

    bridge_ids_by_host: dict[str, list[str]] = {}
    for node in nodes.values():
        if node.cloud != Cloud.CROSS_CLOUD:
            continue
        # AWSCollector's federated bridge nodes: id "federated:<Federated principal>"
        # GCPCollector's (task 8) WIF bridge nodes: id "gcp:wif_bridge:<issuer_uri>"
        if not (node.id.startswith("federated:") or node.id.startswith(GCP_WIF_BRIDGE_PREFIX)):
            continue
        host = _oidc_host(node.name) or _oidc_host(node.id)
        if host:
            bridge_ids_by_host.setdefault(host, []).append(node.id)

    remap: dict[str, str] = {}
    for host, ids in bridge_ids_by_host.items():
        if len(ids) < 2:
            continue  # nothing to merge -- only one cloud saw this issuer
        canonical_id = f"cross_cloud:oidc_bridge:{host}"
        source = nodes[ids[0]]
        nodes[canonical_id] = Node(
            id=canonical_id,
            type=source.type,
            cloud=Cloud.CROSS_CLOUD,
            name=host,
            external_facing=True,
            attributes={"issuer_host": host, "merged_from": sorted(ids)},
        )
        for old_id in ids:
            remap[old_id] = canonical_id
            nodes.pop(old_id, None)
        logger.info("Merged %d bridge node(s) for issuer host %s -> %s", len(ids), host, canonical_id)

    if remap:
        edges = [
            replace(e, source=remap.get(e.source, e.source), target=remap.get(e.target, e.target)) for e in edges
        ]

    return nodes, edges


def merge_direct_references(nodes: dict[str, Node], edges: list[Edge]) -> list[Edge]:
    """
    Pattern 2/3 shape: rewrite an edge's foreign-cloud endpoint straight to
    a matching node when one cloud's condition/attributes embed a literal
    reference (ARN, WIF resource path) resolvable in the other cloud's
    already-collected nodes. Returns a new edge list; does not add nodes
    (the referenced node must already exist -- if it doesn't, the
    reference can't be resolved and the raw edge is left as collected).
    """
    arn_by_suffix: dict[str, str] = {}
    for node in nodes.values():
        arn = node.attributes.get("arn") if node.attributes else None
        if arn:
            arn_by_suffix[arn] = node.id

    resolved = []
    for e in edges:
        if e.type != EdgeType.FEDERATES_WITH or not e.condition:
            resolved.append(e)
            continue
        match = None
        for arn, node_id in arn_by_suffix.items():
            if arn and arn in e.condition:
                match = node_id
                break
        if match and match != e.target:
            logger.info("Direct-reference correlation: %s condition names %s -> rewriting target", e.source, match)
            resolved.append(replace(e, target=match, evidence=(e.evidence or "") + " [direct ARN reference match]"))
        else:
            resolved.append(e)
    return resolved


def tag_confidence(edges: list[Edge]) -> tuple[list[Edge], list[AdvisoryNote]]:
    """
    Assign a Confidence tier + matching risk_weight to every FEDERATES_WITH
    edge, using the cloud that actually holds the scoping condition (the
    edge's own `cloud` may be CROSS_CLOUD post-merge, so we score using
    whichever of the two condition-shape parsers matches; AWS conditions
    are JSON, GCP conditions are a CEL expression string -- try both,
    JSON-decodable wins the AWS parser).

    LOW-confidence edges are pulled out of the returned edge list entirely
    -- per docs/THREAT_MODEL.md #4, a LOW-confidence guess is never
    promoted into pathfinder traversal -- and reported back as
    AdvisoryNotes instead.
    """
    kept: list[Edge] = []
    advisories: list[AdvisoryNote] = []

    for e in edges:
        if e.type != EdgeType.FEDERATES_WITH:
            kept.append(e)
            continue

        confidence = _score_edge(e)

        if confidence == Confidence.LOW:
            advisories.append(
                AdvisoryNote(
                    node_a=e.source,
                    node_b=e.target,
                    reason=e.evidence or "Federation edge present but condition does not narrow the subject",
                )
            )
            continue

        kept.append(
            replace(
                e,
                risk_weight=RISK_WEIGHT_BY_CONFIDENCE[confidence],
                attributes={**e.attributes, "confidence": confidence.value},
            )
        )

    return kept, advisories


def _score_edge(e: Edge) -> Confidence:
    if e.condition and e.condition.strip().startswith("{"):
        return score_aws_condition(e.condition)
    # aws_account_id: set by gcp_collector.py's AWS-type-provider branch
    # (see _emit_workload_identity_edge) on the edges it emits -- an
    # AWS-type WIF provider is always scoped to exactly one AWS account
    # at the provider level, so score_gcp_condition needs this to
    # correctly floor an empty/unrecognized condition to MEDIUM instead
    # of LOW rather than treating it as "no evidence of scoping at all."
    aws_account_id = e.attributes.get("aws_account_id") if e.attributes else None
    return score_gcp_condition(e.condition, aws_account_id=aws_account_id)


def correlate(nodes: list[Node], edges: list[Edge]) -> tuple[list[Node], list[Edge], list[AdvisoryNote]]:
    """
    Main entrypoint. Takes the *combined* node/edge lists from every
    collector that ran (AWSCollector, GCPCollector, ...) and returns a
    single connected, confidence-tagged graph ready for the escalation
    rule engine (task 10) and pathfinder (task 11).
    """
    node_map = {n.id: n for n in nodes}

    node_map, edges = merge_oidc_bridges(node_map, edges)
    edges = merge_direct_references(node_map, edges)
    edges, advisories = tag_confidence(edges)

    return list(node_map.values()), edges, advisories
