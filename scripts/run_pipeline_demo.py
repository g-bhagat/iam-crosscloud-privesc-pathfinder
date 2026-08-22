#!/usr/bin/env python3
"""
run_pipeline_demo.py

End-to-end demo of tasks 9-12 (correlation -> escalation rules ->
pathfinder -> pyvis export) against sample_data/sample_graph.json --
useful for a quick sanity check, and for regenerating the sanitized
screenshot used in the portfolio site (task 22).

This is a stand-in for the real pipeline entrypoint (task 19: "Run full
pipeline (collectors -> graph -> correlation -> escalation rules ->
pathfinder) against sandbox") until AWSCollector/GCPCollector (tasks 7-8)
can run against real sandbox credentials -- swap the sample_graph.json
load below for AWSCollector(...).collect() + GCPCollector(...).collect()
once those exist.

    python3 scripts/run_pipeline_demo.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.analysis.correlation import correlate
from src.analysis.escalation_rules import run_all
from src.analysis.pathfinder import find_escalation_paths
from src.graph_schema import Edge, Node
from src.visualization.pyvis_export import export_graph

SAMPLE_GRAPH_PATH = Path(__file__).resolve().parent.parent / "sample_data" / "sample_graph.json"
OUTPUT_HTML_PATH = Path(__file__).resolve().parent.parent / "sample_data" / "sample_graph_visualization.html"


def main():
    data = json.loads(SAMPLE_GRAPH_PATH.read_text())
    raw_nodes = [Node.from_dict(n) for n in data["nodes"]]
    raw_edges = [Edge.from_dict(e) for e in data["edges"]]
    print(f"Loaded {len(raw_nodes)} nodes, {len(raw_edges)} edges from {SAMPLE_GRAPH_PATH.name}")

    nodes, edges, advisories = correlate(raw_nodes, raw_edges)
    print("\n--- Correlation (task 9) ---")
    print(f"{len(nodes)} nodes, {len(edges)} edges after merge; {len(advisories)} LOW-confidence advisory note(s)")
    for a in advisories:
        print(f"  advisory: {a.node_a} <-> {a.node_b}: {a.reason}")

    result = run_all(nodes, edges)
    print("\n--- Escalation rule engine (task 10) ---")
    print(f"{len(result.findings)} finding(s):")
    for f in result.findings:
        print(f"  [{f.severity.value.upper()}] Pattern {f.pattern_id} ({f.pattern_name})")
        print(f"    {f.source_node} -> {f.target_node}  (confidence: {f.confidence.value})")
        print(f"    {f.evidence}")
        print(f"    MITRE: {f.mitre_attack}")
        print(f"    NIST/CIS: {f.nist_cis}")
    print(f"\n{len(result.skipped_patterns)} pattern(s) deferred (documented, not built):")
    for pid, name, reason in result.skipped_patterns:
        print(f"  Pattern {pid} ({name}): {reason}")

    paths = find_escalation_paths(nodes, edges, external_facing_only=True)
    print("\n--- Pathfinder (task 11) ---")
    print(f"{len(paths)} path(s) from external-facing nodes to admin-equivalent identities:")
    for p in paths:
        print(f"  cost={p.total_risk_weight:.2f}  {p}")

    highlight = set(paths[0].node_ids) if paths else set()
    out = export_graph(nodes, edges, OUTPUT_HTML_PATH, highlight_node_ids=highlight)
    print("\n--- Visualization (task 12) ---")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
