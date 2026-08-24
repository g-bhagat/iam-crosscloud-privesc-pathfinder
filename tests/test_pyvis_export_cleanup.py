"""
Tests for the two rendering cleanups on top of the raw collector/
correlation output: merging self-loop edges (an AdministratorAccess-style
holder otherwise renders one overlapping loop per matched action) and
hiding zero-degree nodes by default.
"""

from src.graph_schema import Cloud, Edge, EdgeType, Node, NodeType
from src.visualization.pyvis_export import (
    _merge_self_loops,
    _nodes_with_any_edge,
    export_graph,
)


def _admin_access_node_and_self_loops(node_id: str = "aws:user:arn:aws:iam::123456789012:user/admin-bot"):
    """Mirrors AWSCollector._emit_sensitive_edges: an AdministratorAccess
    holder matches every entry in SENSITIVE_ACTIONS at once, producing one
    self-loop per action -- 10 in the real SENSITIVE_ACTIONS dict."""
    actions = [
        "iam:PassRole",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAssumeRolePolicy",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "sts:AssumeRole",
    ]
    edge_types = [
        EdgeType.CAN_PASS_ROLE,
        EdgeType.CAN_MODIFY_POLICY,
        EdgeType.CAN_MODIFY_POLICY,
        EdgeType.CAN_MODIFY_TRUST,
        EdgeType.CAN_ATTACH_POLICY,
        EdgeType.CAN_ATTACH_POLICY,
        EdgeType.CAN_ATTACH_POLICY,
        EdgeType.CAN_ATTACH_POLICY,
        EdgeType.CAN_ATTACH_POLICY,
        EdgeType.CAN_ASSUME,
    ]
    loops = [
        Edge(
            source=node_id, target=node_id, type=t, cloud=Cloud.AWS,
            risk_weight=0.5, evidence=f"Holds action '{a}'",
        )
        for a, t in zip(actions, edge_types)
    ]
    return node_id, loops


def test_merge_self_loops_collapses_many_into_one():
    node_id, loops = _admin_access_node_and_self_loops()
    merged = _merge_self_loops(loops)

    self_loop_edges = [e for e in merged if e.source == node_id and e.target == node_id]
    assert len(self_loop_edges) == 1, f"expected one merged self-loop, got {len(self_loop_edges)}"


def test_merged_self_loop_tooltip_lists_every_action():
    _node_id, loops = _admin_access_node_and_self_loops()
    merged = _merge_self_loops(loops)
    combined = merged[0]

    for a in ["iam:PassRole", "iam:CreatePolicyVersion", "iam:AttachRolePolicy", "sts:AssumeRole"]:
        assert a in combined.evidence
    assert combined.attributes["merged_capability_count"] == 10


def test_merge_self_loops_leaves_single_self_loop_untouched():
    edge = Edge(source="x", target="x", type=EdgeType.CAN_ASSUME, cloud=Cloud.AWS, evidence="Holds action 'sts:AssumeRole'")
    merged = _merge_self_loops([edge])
    assert merged == [edge]


def test_merge_self_loops_does_not_touch_distinct_node_pairs():
    """Two separate CAN_ASSUME grants between two DIFFERENT real nodes are
    not self-loops and must stay separate, individually meaningful edges."""
    e1 = Edge(source="a", target="b", type=EdgeType.CAN_ASSUME, cloud=Cloud.AWS, condition="cond-1")
    e2 = Edge(source="a", target="b", type=EdgeType.CAN_ASSUME, cloud=Cloud.AWS, condition="cond-2")
    merged = _merge_self_loops([e1, e2])
    assert len(merged) == 2


def test_merge_self_loops_dedupes_identical_type_and_evidence():
    node_id = "x"
    e1 = Edge(source=node_id, target=node_id, type=EdgeType.CAN_ATTACH_POLICY, cloud=Cloud.AWS, evidence="Holds action 'iam:AttachUserPolicy'")
    e2 = Edge(source=node_id, target=node_id, type=EdgeType.CAN_ATTACH_POLICY, cloud=Cloud.AWS, evidence="Holds action 'iam:AttachUserPolicy'")
    merged = _merge_self_loops([e1, e2])
    assert len(merged) == 1
    assert merged[0].attributes["merged_capability_count"] == 1


def test_merge_self_loops_keeps_separate_nodes_independent():
    """Two different nodes each with their own self-loops must not bleed
    into each other's merged edge."""
    a_loops = [
        Edge(source="a", target="a", type=EdgeType.CAN_PASS_ROLE, cloud=Cloud.AWS, evidence="Holds action 'iam:PassRole'"),
        Edge(source="a", target="a", type=EdgeType.CAN_ASSUME, cloud=Cloud.AWS, evidence="Holds action 'sts:AssumeRole'"),
    ]
    b_loop = [Edge(source="b", target="b", type=EdgeType.CAN_ATTACH_POLICY, cloud=Cloud.AWS, evidence="Holds action 'iam:AttachRolePolicy'")]

    merged = _merge_self_loops(a_loops + b_loop)
    a_merged = [e for e in merged if e.source == "a"]
    b_merged = [e for e in merged if e.source == "b"]
    assert len(a_merged) == 1 and a_merged[0].attributes["merged_capability_count"] == 2
    assert len(b_merged) == 1 and "merged_capability_count" not in b_merged[0].attributes


def test_export_graph_renders_one_edge_label_for_admin_access_holder(tmp_path):
    node_id, loops = _admin_access_node_and_self_loops()
    node = Node(id=node_id, type=NodeType.USER, cloud=Cloud.AWS, name="admin-bot", is_admin=True)

    out = export_graph([node], loops, tmp_path / "admin.html")
    html = out.read_text()
    # One combined label ("10 capabilities"), not 10 overlapping
    # per-action edge labels like "can_pass_role", "can_attach_policy", ...
    assert "10 capabilities" in html
    assert '"label": "can_pass_role"' not in html
    assert '"label": "can_attach_policy"' not in html
    # The breakdown by type IS expected inside the combined tooltip text --
    # that's the point of merging rather than dropping the detail.
    assert "iam:PassRole" in html
    assert "iam:AttachRolePolicy" in html


def test_nodes_with_any_edge_counts_self_loops():
    edge = Edge(source="x", target="x", type=EdgeType.CAN_ASSUME, cloud=Cloud.AWS)
    assert _nodes_with_any_edge([edge]) == {"x"}


def test_isolated_node_with_no_edges_at_all_is_excluded_by_nodes_with_any_edge():
    edge = Edge(source="a", target="b", type=EdgeType.CAN_ASSUME, cloud=Cloud.AWS)
    touched = _nodes_with_any_edge([edge])
    assert "isolated-node" not in touched


def test_export_graph_hides_isolated_node_by_default(tmp_path):
    connected_a = Node(id="a", type=NodeType.ROLE, cloud=Cloud.AWS, name="connected-a")
    connected_b = Node(id="b", type=NodeType.ROLE, cloud=Cloud.AWS, name="connected-b")
    isolated = Node(id="c", type=NodeType.ROLE, cloud=Cloud.AWS, name="totally-isolated-node")
    edge = Edge(source="a", target="b", type=EdgeType.CAN_ASSUME, cloud=Cloud.AWS)

    out = export_graph([connected_a, connected_b, isolated], [edge], tmp_path / "hide.html")
    html = out.read_text()
    assert "connected-a" in html and "connected-b" in html
    assert "totally-isolated-node" not in html


def test_export_graph_shows_isolated_node_when_requested(tmp_path):
    connected_a = Node(id="a", type=NodeType.ROLE, cloud=Cloud.AWS, name="connected-a")
    connected_b = Node(id="b", type=NodeType.ROLE, cloud=Cloud.AWS, name="connected-b")
    isolated = Node(id="c", type=NodeType.ROLE, cloud=Cloud.AWS, name="totally-isolated-node")
    edge = Edge(source="a", target="b", type=EdgeType.CAN_ASSUME, cloud=Cloud.AWS)

    out = export_graph(
        [connected_a, connected_b, isolated], [edge], tmp_path / "show.html", show_isolated_nodes=True
    )
    assert "totally-isolated-node" in out.read_text()


def test_node_with_only_a_self_loop_is_not_treated_as_isolated(tmp_path):
    """A self-loop IS an edge touching the node (source==target) -- a node
    with only a self-loop marker still carries signal (e.g. 'this identity
    holds AdministratorAccess') and must stay visible by default."""
    node = Node(id="x", type=NodeType.USER, cloud=Cloud.AWS, name="admin-only-self-loop")
    loop = Edge(source="x", target="x", type=EdgeType.CAN_ATTACH_POLICY, cloud=Cloud.AWS, evidence="Holds action 'iam:AttachRolePolicy'")

    out = export_graph([node], [loop], tmp_path / "self_loop_only.html")
    assert "admin-only-self-loop" in out.read_text()
