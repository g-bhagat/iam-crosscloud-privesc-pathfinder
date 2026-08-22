from src.analysis.correlation import correlate
from src.analysis.pathfinder import find_escalation_paths, reachable_admin_nodes


def test_finds_cross_cloud_path_to_owner_sa(sample_graph):
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)

    paths = find_escalation_paths(merged_nodes, merged_edges, external_facing_only=True)
    owner_paths = [p for p in paths if "track1-owner-sa" in p.target]
    assert owner_paths, "expected at least one path to the owner SA from an external-facing node"

    # The canonical OIDC bridge node should be the source (it's the only
    # external_facing node that fans out toward both clouds).
    assert any("oidc_bridge" in p.source for p in owner_paths)


def test_no_path_to_unreachable_admin_node(sample_graph):
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)

    paths = find_escalation_paths(merged_nodes, merged_edges)
    assert not any("legacy-break-glass" in p.target for p in paths)


def test_in_cloud_membership_path_is_generic_not_cross_cloud_specific(sample_graph):
    """sam-devops -> break-glass-admins is pure AWS group membership, no
    federation at all -- pathfinder must still find it, proving it's not
    hardcoded to cross-cloud edges."""
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)

    paths = find_escalation_paths(merged_nodes, merged_edges)
    sam_paths = [p for p in paths if "sam-devops" in p.source and "break-glass-admins" in p.target]
    assert len(sam_paths) == 1
    assert sam_paths[0].node_ids[0].endswith("sam-devops")


def test_reachable_admin_nodes_excludes_unreachable(sample_graph):
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)

    bridge_id = next(n.id for n in merged_nodes if n.id.startswith("cross_cloud:oidc_bridge:"))
    reachable = reachable_admin_nodes(merged_nodes, merged_edges, bridge_id)

    assert any("track1-owner-sa" in r for r in reachable)
    assert not any("legacy-break-glass" in r for r in reachable)
    assert not any("track1-scoped-sa" in r for r in reachable)  # not is_admin


def test_cheapest_path_ranks_first(sample_graph):
    """The MEDIUM-confidence (loose) edge has a lower risk_weight than a
    HIGH-confidence one -- if there were multiple admin targets, the
    cheaper path should sort first. With one admin target this just
    confirms total_risk_weight matches the single loose edge's weight."""
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)

    paths = find_escalation_paths(merged_nodes, merged_edges, external_facing_only=True)
    owner_path = next(p for p in paths if "track1-owner-sa" in p.target)
    assert owner_path.total_risk_weight < 1.0  # cheaper than a HIGH-confidence (1.0) edge
