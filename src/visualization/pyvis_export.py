"""
pyvis_export.py -- task 12

Exports a correlated identity graph to an interactive HTML visualization
via pyvis. Meant for two audiences: the analyst exploring findings
locally, and sanitized screenshots for the portfolio site (docs/) --
callers are responsible for sanitizing node/edge attributes (real account
IDs, ARNs, project IDs) before anything generated here is published,
per SCOPE.md rule 5. Nothing in this module does that sanitization itself.

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
"""

from __future__ import annotations

from pathlib import Path

from pyvis.network import Network

from ..graph_schema import Cloud, Edge, Node

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


def export_graph(
    nodes: list[Node],
    edges: list[Edge],
    output_path: str | Path,
    highlight_node_ids: set[str] | None = None,
    title: str = "Cross-Cloud IAM Privilege Escalation Graph",
) -> Path:
    """
    Render `nodes`/`edges` (post correlation.correlate(), ideally) to an
    interactive HTML file at `output_path`. `highlight_node_ids` -- e.g.
    the node_ids of an EscalationPath from pathfinder.py -- get a thick red
    border so a specific finding is visually traceable.
    """
    highlight_node_ids = highlight_node_ids or set()

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

    for e in edges:
        if e.source not in {n.id for n in nodes} or e.target not in {n.id for n in nodes}:
            continue  # skip dangling references rather than let pyvis raise
        confidence = e.attributes.get("confidence") if e.attributes else None
        color = CONFIDENCE_EDGE_COLOR.get(confidence, DEFAULT_EDGE_COLOR)
        weight = e.risk_weight if e.risk_weight is not None else 1.0
        # Inverse: cheaper (more exploitable) edges render thicker.
        width = max(1.0, 5.0 - (weight * 3.0))

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
