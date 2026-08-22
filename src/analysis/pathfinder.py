"""
pathfinder.py -- task 11

Generic graph walk from any node to an is_admin=True node, using each
edge's risk_weight as traversal cost (graph_schema.py's contract: lower
weight = easier/likelier to exploit). Built on networkx so the actual
shortest-path algorithm (Dijkstra) is a well-tested library call, not a
hand-rolled one -- the value this module adds is in *how* the graph is
built and *which* paths are worth reporting, not in reimplementing
Dijkstra.

Deliberately cloud-agnostic: nothing here is Pattern-1/2-specific (that
lives in escalation_rules.py). A path can be pure in-cloud (e.g. AWS user
-> group -> admin group, no federation at all -- see
sample_data/sample_graph.json's sam-devops/break-glass-admins pair) or
cross-cloud. escalation_rules.py decides which findings matter for the
5-pattern catalog; this module just answers "can X reach an admin node,
and how cheaply."
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

import networkx as nx

from ..graph_schema import Edge, Node


@dataclass
class EscalationPath:
    source: str
    target: str
    node_ids: list[str]
    edge_evidence: list[str]
    total_risk_weight: float

    def __str__(self) -> str:
        return " -> ".join(self.node_ids)


def build_graph(nodes: list[Node], edges: list[Edge]) -> nx.DiGraph:
    g = nx.DiGraph()
    for n in nodes:
        g.add_node(n.id, node=n)
    for e in edges:
        if e.source not in g or e.target not in g:
            continue  # dangling reference (e.g. an unresolved direct-reference edge) -- skip, don't crash
        weight = e.risk_weight if e.risk_weight is not None else 1.0
        # A node pair can have multiple edges (e.g. two IAM statements). Keep
        # the cheapest (most exploitable) one for path-cost purposes.
        if g.has_edge(e.source, e.target) and weight >= g[e.source][e.target]["weight"]:
            continue
        g.add_edge(e.source, e.target, weight=weight, edge=e)
    return g


def find_escalation_paths(
    nodes: list[Node],
    edges: list[Edge],
    sources: list[str] | None = None,
    external_facing_only: bool = False,
) -> list[EscalationPath]:
    """
    Compute the cheapest (min total risk_weight) path from each candidate
    source node to every is_admin=True node it can reach.

    sources: explicit list of source node IDs. If omitted, every node is a
        candidate source (task 11's literal "from any node").
    external_facing_only: if True and `sources` is omitted, restrict
        candidate sources to nodes with external_facing=True -- the
        practically meaningful question for a threat model ("what can an
        attacker who compromises this externally-reachable identity
        reach"), since almost every node is technically able to walk a
        capability graph in the mathematical sense.
    """
    g = build_graph(nodes, edges)

    admin_ids = [n.id for n in nodes if n.is_admin]
    if not admin_ids:
        return []

    if sources is None:
        if external_facing_only:
            candidate_sources = [n.id for n in nodes if n.external_facing]
        else:
            candidate_sources = list(g.nodes)
    else:
        candidate_sources = sources

    paths: list[EscalationPath] = []
    for source_id in candidate_sources:
        if source_id not in g:
            continue
        try:
            lengths, path_map = nx.single_source_dijkstra(g, source_id, weight="weight")
        except nx.NodeNotFound:
            continue

        for admin_id in admin_ids:
            if admin_id == source_id or admin_id not in path_map:
                continue
            node_ids = path_map[admin_id]
            if len(node_ids) < 2:
                continue

            evidence = []
            for a, b in pairwise(node_ids):
                e: Edge = g[a][b]["edge"]
                evidence.append(e.evidence or f"{e.type.value} ({a} -> {b})")

            paths.append(
                EscalationPath(
                    source=source_id,
                    target=admin_id,
                    node_ids=node_ids,
                    edge_evidence=evidence,
                    total_risk_weight=lengths[admin_id],
                )
            )

    # Cheapest (most exploitable) paths first.
    paths.sort(key=lambda p: p.total_risk_weight)
    return paths


def reachable_admin_nodes(nodes: list[Node], edges: list[Edge], source_id: str) -> set[str]:
    """All is_admin=True node IDs reachable from source_id, regardless of cost."""
    g = build_graph(nodes, edges)
    if source_id not in g:
        return set()
    reachable = nx.descendants(g, source_id)
    return {n.id for n in nodes if n.is_admin and n.id in reachable}
