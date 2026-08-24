"""
pyvis_export.py -- task 12

Exports a correlated identity graph to an interactive HTML visualization
via pyvis. Meant for two audiences: the analyst exploring findings
locally, and sanitized screenshots for the portfolio site (docs/) --
pass `sanitize=True` to mask real account IDs, ARNs, and project IDs
(via src/sanitize.py) before anything reaches the output file, per
SCOPE.md rule 5. Defaults to False (raw output) because a raw export is
still the right choice for the analyst's own local inspection -- this
module doesn't force sanitization, callers publishing anywhere decide.

Visual encoding:
  - node color = cloud (AWS orange, GCP blue, Azure teal, cross-cloud
    bridge purple)
  - node shape = is_admin (a red-bordered star) vs. everything else (a dot)
  - edge color = confidence tier for FEDERATES_WITH edges (red = MEDIUM
    i.e. the dangerous "resolves to a set" case, orange = HIGH, gray for
    everything else); edge width scales inversely with risk_weight so the
    cheapest/most-exploitable edges visually pop
  - highlighted escalation paths (from pathfinder.py) get a thicker red
    outline so the finding is legible without reading the JSON

Two cleanups on top of the raw node/edge lists, both because the raw
collector output isn't shaped for a legible picture even though it's
exactly right for the analysis layer:
  - self-loop edges (AWSCollector/_emit_sensitive_edges,
    GCPCollector/_process_iam_policy_search_result -- both mark "this
    identity holds capability X" as source==target) collapse to ONE
    rendered edge per node, not one per action. A single
    AdministratorAccess/roles/owner holder can otherwise match every
    entry in SENSITIVE_ACTIONS/HIGH_PRIV_GCP_ROLES at once and render as
    a dense knot of overlapping loops on one node. The merged edge's
    tooltip lists every distinct capability.
  - zero-degree nodes (no edge touches them at all -- not even a
    self-loop) are hidden by default (`show_isolated_nodes=False`).
    They add clutter without signal: nothing points at them and they
    point at nothing, so they can never be part of a rendered escalation
    path. Pass `show_isolated_nodes=True` to include them back.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

from pyvis.network import Network

from ..graph_schema import Cloud, Edge, Node
from ..sanitize import sanitize_graph

logger = logging.getLogger(__name__)

CLOUD_COLOR = {
    Cloud.AWS: "#FF9900",
    Cloud.GCP: "#4285F4",
    Cloud.AZURE: "#008AD7",
    Cloud.CROSS_CLOUD: "#8B5CF6",
}

CONFIDENCE_EDGE_COLOR = {
    "high": "#F59E0B",    # tightly scoped -- still worth a look, not the headline risk
    "medium": "#DC2626",  # loosely scoped -- the dangerous, ambiguous-principal-set case
}
DEFAULT_EDGE_COLOR = "#9CA3AF"


def _nodes_with_any_edge(edges: list[Edge]) -> set[str]:
    touched: set[str] = set()
    for e in edges:
        touched.add(e.source)
        touched.add(e.target)
    return touched


def _merge_self_loops(edges: list[Edge]) -> list[Edge]:
    """Collapse every self-loop (source == target) sharing a node into one
    edge, combining their evidence into a single tooltip. Non-self-loop
    edges pass through untouched -- this only targets the "holds N
    capabilities" self-loop pattern, not general multi-edge pairs (two
    distinct CAN_ASSUME grants between two different real nodes are still
    two separate, individually meaningful edges)."""
    self_loops_by_node: dict[str, list[Edge]] = defaultdict(list)
    other_edges: list[Edge] = []
    for e in edges:
        if e.source == e.target:
            self_loops_by_node[e.source].append(e)
        else:
            other_edges.append(e)

    merged: list[Edge] = []
    for node_id, loop_edges in self_loops_by_node.items():
        if len(loop_edges) == 1:
            merged.append(loop_edges[0])
            continue
        # Dedupe identical (type, evidence) pairs -- defensive, in case a
        # collector ever emits the same capability marker twice.
        seen: list[tuple[str, str]] = []
        for e in loop_edges:
            entry = (e.type.value, e.evidence or "")
            if entry not in seen:
                seen.append(entry)
        tooltip = "\n".join(f"{t}: {ev}" if ev else t for t, ev in seen)
        cheapest = min((e.risk_weight for e in loop_edges if e.risk_weight is not None), default=1.0)
        merged.append(
            Edge(
                source=node_id,
                target=node_id,
                type=loop_edges[0].type,
                cloud=loop_edges[0].cloud,
                risk_weight=cheapest,
                evidence=tooltip,
                attributes={"merged_capability_count": len(seen)},
            )
        )
    return merged + other_edges


def export_graph(
    nodes: list[Node],
    edges: list[Edge],
    output_path: str | Path,
    highlight_node_ids: set[str] | None = None,
    title: str = "Cross-Cloud IAM Privilege Escalation Graph",
    sanitize: bool = False,
    show_isolated_nodes: bool = False,
) -> Path:
    """
    Render `nodes`/`edges` (post correlation.correlate(), ideally) to an
    interactive HTML file at `output_path`. `highlight_node_ids` -- e.g.
    the node_ids of an EscalationPath from pathfinder.py -- get a thick red
    border so a specific finding is visually traceable.

    sanitize: if True, mask real account IDs/ARNs/project IDs (see
        src/sanitize.py) before anything is written out. Pass
        `highlight_node_ids` computed from the SAME (pre-sanitize) nodes
        you're passing in here -- this function translates them through
        the same mapping internally, so they still match after
        sanitization changes the node IDs.

    show_isolated_nodes: if False (default), nodes with no edge touching
        them at all -- not even a self-loop -- are dropped from the
        rendered view. They add clutter without signal: nothing points at
        them, they point at nothing, so they can never appear in a
        rendered escalation path. A logged message reports how many were
        hidden; pass True to include them.
    """
    highlight_node_ids = highlight_node_ids or set()

    if sanitize:
        nodes, edges, sanitizer = sanitize_graph(nodes, edges)
        highlight_node_ids = {sanitizer.sanitize_text(nid) for nid in highlight_node_ids}

    edges = _merge_self_loops(edges)

    if not show_isolated_nodes:
        connected = _nodes_with_any_edge(edges)
        hidden = [n for n in nodes if n.id not in connected]
        if hidden:
            logger.info(
                "Hiding %d isolated node(s) with no edges (pass show_isolated_nodes=True to include them): %s",
                len(hidden),
                ", ".join(n.name for n in hidden[:10]) + (", ..." if len(hidden) > 10 else ""),
            )
        nodes = [n for n in nodes if n.id in connected]

    net = Network(
        height="850px",
        width="100%",
        directed=True,
        notebook=False,
        bgcolor="#0B0F19",
        font_color="#E5E7EB",
        # Inline vis.js/tom-select into the single output file instead of
        # writing a sibling lib/ directory relative to cwd -- keeps this a
        # one-file, portable artifact and keeps repeated local runs from
        # scattering vendored JS into the repo root.
        cdn_resources="in_line",
    )
    net.heading = title
    net.barnes_hut(gravity=-6000, central_gravity=0.2, spring_length=140, spring_strength=0.02, damping=0.25)

    for n in nodes:
        color = CLOUD_COLOR.get(n.cloud, "#6B7280")
        shape = "star" if n.is_admin else ("triangle" if n.external_facing else "dot")
        border_color = "#EF4444" if n.id in highlight_node_ids else color
        border_width = 4 if n.id in highlight_node_ids else 1

        tooltip_lines = [
            f"{n.name}",
            f"type: {n.type.value}",
            f"cloud: {n.cloud.value}",
            f"admin: {n.is_admin}",
        ]
        if n.external_facing:
            tooltip_lines.append("external-facing")
        if n.mfa_enabled is False:
            tooltip_lines.append("MFA disabled")

        net.add_node(
            n.id,
            label=n.name,
            title="\n".join(tooltip_lines),
            color={"background": color, "border": border_color},
            borderWidth=border_width,
            shape=shape,
            size=26 if n.is_admin else 16,
        )

    rendered_node_ids = {n.id for n in nodes}
    for e in edges:
        if e.source not in rendered_node_ids or e.target not in rendered_node_ids:
            continue  # skip dangling references (or an isolated-node's own edges, now hidden) rather than let pyvis raise
        confidence = e.attributes.get("confidence") if e.attributes else None
        color = CONFIDENCE_EDGE_COLOR.get(confidence, DEFAULT_EDGE_COLOR)
        weight = e.risk_weight if e.risk_weight is not None else 1.0
        # Inverse: cheaper (more exploitable) edges render thicker.
        width = max(1.0, 5.0 - (weight * 3.0))

        capability_count = e.attributes.get("merged_capability_count") if e.attributes else None
        if capability_count:
            # A merged self-loop: e.type is only the first of several
            # distinct capability types it now represents, so label by
            # count instead -- the full breakdown is in the tooltip.
            label = f"{capability_count} capabilities"
        else:
            label = e.type.value
            if confidence:
                label += f" ({confidence})"

        net.add_edge(
            e.source,
            e.target,
            label=label,
            title=e.evidence or "",
            color=color,
            width=width,
            arrows="to",
        )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(output_path), open_browser=False, notebook=False)
    return output_path
