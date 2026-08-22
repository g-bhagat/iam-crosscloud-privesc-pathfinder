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
