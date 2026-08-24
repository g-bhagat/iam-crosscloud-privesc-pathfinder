from src.analysis.correlation import correlate
from src.analysis.pathfinder import find_escalation_paths
from src.visualization.pyvis_export import export_graph


def test_export_graph_writes_html(sample_graph, tmp_path):
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)
    paths = find_escalation_paths(merged_nodes, merged_edges, external_facing_only=True)
    highlight = set(paths[0].node_ids) if paths else set()

    out = export_graph(merged_nodes, merged_edges, tmp_path / "graph.html", highlight_node_ids=highlight)

    assert out.exists()
    html = out.read_text()
    assert "track1-owner-sa" in html
    assert "vis-network" in html or "vis.js" in html or "network" in html.lower()


def test_isolated_node_hidden_by_default(sample_graph, tmp_path):
    """sample_graph.json's legacy-break-glass role has no edges at all
    (deliberately, per generate_sample_graph.py) -- must not render."""
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)

    out = export_graph(merged_nodes, merged_edges, tmp_path / "default.html")
    assert "legacy-break-glass" not in out.read_text()


def test_isolated_node_shown_when_requested(sample_graph, tmp_path):
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)

    out = export_graph(merged_nodes, merged_edges, tmp_path / "with_isolated.html", show_isolated_nodes=True)
    assert "legacy-break-glass" in out.read_text()
