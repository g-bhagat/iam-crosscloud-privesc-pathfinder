from src.graph_schema import Cloud, Edge, EdgeType, Node, NodeType
from src.visualization.pyvis_export import export_graph


def _track1_shaped_graph():
    bridge = Node(
        id="cross_cloud:oidc_bridge:token.actions.githubusercontent.com",
        type=NodeType.APP_REGISTRATION,
        cloud=Cloud.CROSS_CLOUD,
        name="token.actions.githubusercontent.com",
        external_facing=True,
    )
    owner_sa = Node(
        id="gcp:service_account:track1-owner-sa@iam-pathfinder-sandbox.iam.gserviceaccount.com",
        type=NodeType.SERVICE_ACCOUNT,
        cloud=Cloud.GCP,
        name="track1-owner-sa@iam-pathfinder-sandbox.iam.gserviceaccount.com",
        is_admin=True,
    )
    edge = Edge(
        source=bridge.id,
        target=owner_sa.id,
        type=EdgeType.FEDERATES_WITH,
        cloud=Cloud.CROSS_CLOUD,
        condition='assertion.repository_owner == "acme-corp"',
        attributes={"confidence": "medium"},
    )
    return [bridge, owner_sa], [edge]


def test_sanitize_false_leaves_real_project_id_in_output(tmp_path):
    nodes, edges = _track1_shaped_graph()
    out = export_graph(nodes, edges, tmp_path / "raw.html", sanitize=False)
    assert "iam-pathfinder-sandbox" in out.read_text()


def test_sanitize_true_masks_real_project_id_in_output(tmp_path):
    nodes, edges = _track1_shaped_graph()
    out = export_graph(nodes, edges, tmp_path / "sanitized.html", sanitize=True)
    html = out.read_text()
    assert "iam-pathfinder-sandbox" not in html
    assert "sanitized-gcp-project-1" in html


def test_highlight_node_ids_still_match_after_sanitization(tmp_path):
    """highlight_node_ids computed from the ORIGINAL (pre-sanitize) node ids
    must still highlight the right node once export_graph sanitizes
    internally -- the node IDs themselves change under sanitization."""
    nodes, edges = _track1_shaped_graph()
    owner_sa_id = nodes[1].id  # the real, pre-sanitize id

    out = export_graph(nodes, edges, tmp_path / "highlighted.html", sanitize=True, highlight_node_ids={owner_sa_id})
    html = out.read_text()
    # The sanitized placeholder node must carry the highlight border color.
    assert "sanitized-gcp-project-1" in html
    assert "#EF4444" in html  # highlight border color actually applied to some node
