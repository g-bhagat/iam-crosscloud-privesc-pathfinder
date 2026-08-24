#!/usr/bin/env python3
"""
run_detector.py

Runs the actual detection pipeline (task 19: correlation -> escalation
rules -> pathfinder -> pyvis export) against REAL data collected from
your sandbox -- not sample_data/sample_graph.json.

Takes the JSON dumps produced by run_aws_collector.py and
run_gcp_collector.py --dump-json, merges them into one graph, and runs
the same analysis stages already exercised against sample data in
run_pipeline_demo.py.

Usage:
    python3 scripts/run_detector.py \\
        --aws-graph /tmp/aws_graph.json \\
        --gcp-graph /tmp/gcp_graph.json \\
        --output /tmp/track1-finding.html

Output defaults to /tmp, not docs/, deliberately. If --output resolves
to anywhere under a docs/ directory, this script forces sanitize=True
on the pyvis export automatically (src/sanitize.py masks real account
IDs/ARNs/project IDs) -- SCOPE.md rule 5 is not optional for anything
that reaches the public portfolio site, so this isn't left to a flag
you have to remember. Pass --sanitize to mask real identifiers for a
non-docs/ output path too (e.g. sharing a screenshot elsewhere); pass
--no-sanitize to force raw output even under docs/ if you've already
sanitized by some other means and don't want double-masking -- use that
override deliberately, not by default.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.analysis.correlation import correlate
from src.analysis.escalation_rules import run_all
from src.analysis.pathfinder import find_escalation_paths
from src.graph_schema import Cloud, Edge, EdgeType, Node, NodeType
from src.visualization.pyvis_export import export_graph


def load_graph(path: str) -> tuple[list[Node], list[Edge]]:
    data = json.loads(Path(path).read_text())

    nodes = [
        Node(
            id=n["id"],
            type=NodeType(n["type"]),
            cloud=Cloud(n["cloud"]),
            name=n["name"],
            is_admin=n.get("is_admin", False),
            mfa_enabled=n.get("mfa_enabled"),
            external_facing=n.get("external_facing", False),
            attributes=n.get("attributes", {}),
        )
        for n in data["nodes"]
    ]
    edges = [
        Edge(
            source=e["source"],
            target=e["target"],
            type=EdgeType(e["type"]),
            cloud=Cloud(e["cloud"]),
            risk_weight=e.get("risk_weight", 1.0),
            condition=e.get("condition"),
            evidence=e.get("evidence"),
            attributes=e.get("attributes", {}),
        )
        for e in data["edges"]
    ]
    return nodes, edges


def merge_graphs(*graphs: tuple[list[Node], list[Edge]]) -> tuple[list[Node], list[Edge]]:
    """Merge multiple collectors' output into one node/edge list, deduping
    nodes by id."""
    merged_nodes: dict[str, Node] = {}
    merged_edges: list[Edge] = []
    for nodes, edges in graphs:
        for n in nodes:
            if n.id in merged_nodes:
                merged_nodes[n.id].attributes.update(n.attributes)
                merged_nodes[n.id].is_admin = merged_nodes[n.id].is_admin or n.is_admin
            else:
                merged_nodes[n.id] = n
        merged_edges.extend(edges)
    return list(merged_nodes.values()), merged_edges


def main():
    parser = argparse.ArgumentParser(description="Run the detection pipeline against real collected data")
    parser.add_argument("--aws-graph", required=True, help="JSON dump from run_aws_collector.py --dump-json")
    parser.add_argument("--gcp-graph", required=True, help="JSON dump from run_gcp_collector.py --dump-json")
    parser.add_argument("--output", default="/tmp/track1-finding.html", help="Where to write the visualization")
    sanitize_group = parser.add_mutually_exclusive_group()
    sanitize_group.add_argument(
        "--sanitize",
        dest="sanitize",
        action="store_true",
        default=None,
        help="Mask real account IDs/ARNs/project IDs in the export, even for a non-docs/ output path",
    )
    sanitize_group.add_argument(
        "--no-sanitize",
        dest="sanitize",
        action="store_false",
        help="Force raw (unmasked) output even if --output resolves under docs/ -- use deliberately",
    )
    args = parser.parse_args()

    output_path = Path(args.output).resolve()
    heading_to_docs = "docs" in output_path.parts
    if args.sanitize is None:
        sanitize = heading_to_docs
    else:
        sanitize = args.sanitize
        if heading_to_docs and not sanitize:
            print(
                f"WARNING: --output ({output_path}) resolves under docs/ but --no-sanitize was passed -- "
                "writing RAW output with real identifiers. This must be sanitized before anything under "
                "docs/ is committed or published (SCOPE.md rule 5)."
            )

    print(f"Loading AWS graph from {args.aws_graph}")
    aws_nodes, aws_edges = load_graph(args.aws_graph)
    print(f"  {len(aws_nodes)} nodes, {len(aws_edges)} edges")

    print(f"Loading GCP graph from {args.gcp_graph}")
    gcp_nodes, gcp_edges = load_graph(args.gcp_graph)
    print(f"  {len(gcp_nodes)} nodes, {len(gcp_edges)} edges")

    nodes, edges = merge_graphs((aws_nodes, aws_edges), (gcp_nodes, gcp_edges))
    print(f"\nMerged graph (pre-correlation): {len(nodes)} nodes, {len(edges)} edges")

    print("\nRunning correlation engine...")
    nodes, edges, advisory_notes = correlate(nodes, edges)
    print(f"  Post-correlation: {len(nodes)} nodes, {len(edges)} edges")
    # LOW confidence, not MEDIUM: these are federation edges with no real
    # structural evidence (a naming coincidence, or a condition that
    # doesn't narrow the subject at all) -- correlation.py never promotes
    # them into the traversal graph at all, so they can't produce a
    # finding. MEDIUM confidence (e.g. Track 1's org-only-scoped provider)
    # IS included in scoring; see docs/THREAT_MODEL.md #4.
    print(f"  {len(advisory_notes)} advisory notes (LOW-confidence, hygiene notes only -- not scored)")

    print("Running escalation rule engine...")
    result = run_all(nodes, edges)
    findings = result.findings
    print(f"  {len(findings)} findings, {len(result.skipped_patterns)} patterns skipped")
    for pattern_id, name, reason in result.skipped_patterns:
        print(f"    skipped pattern {pattern_id} ({name}): {reason}")

    print("Running pathfinder (external-facing sources only)...")
    paths = find_escalation_paths(nodes, edges, external_facing_only=True)
    print(f"  {len(paths)} escalation paths found")

    print("\n=== FINDINGS ===")
    if not findings:
        print("  None. If you expected the Track 1/2 finding here, check:")
        print("  - Did GCPCollector actually reach the loose WIF provider?")
        print("  - Did the correlation engine tag its confidence correctly?")
        print("  - Is the target SA's is_admin flag actually set to True?")
    for f in findings:
        print(f"\n  [{f.severity.value}] {f.pattern_name} (confidence: {f.confidence.value})")
        print(f"    {f.evidence}")
        print(f"    MITRE: {f.mitre_attack}")
        print(f"    NIST/CIS: {f.nist_cis}")

    print(f"\n=== PATHS ({len(paths)}) ===")
    highlight_ids: set[str] = set()
    for p in paths:
        print(f"  {p} (risk_weight={p.total_risk_weight:.2f})")
        highlight_ids.update(p.node_ids)

    print(f"\nExporting visualization to {output_path} (sanitize={sanitize})")
    export_graph(nodes, edges, output_path=output_path, highlight_node_ids=highlight_ids, sanitize=sanitize)
    if sanitize:
        print("Done. Real account IDs/ARNs/project IDs masked (src/sanitize.py).")
    else:
        print("Done. RAW output -- real identifiers are NOT masked. Do not commit or publish this file as-is.")


if __name__ == "__main__":
    main()
