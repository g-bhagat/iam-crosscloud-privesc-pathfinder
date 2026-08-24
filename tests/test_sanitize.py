from src.graph_schema import Cloud, Edge, EdgeType, Node, NodeType
from src.sanitize import GraphSanitizer, sanitize_graph


def test_aws_arn_account_id_masked():
    s = GraphSanitizer()
    out = s.sanitize_text("arn:aws:iam::123456789012:role/track1-cicd-deploy-role")
    assert "123456789012" not in out
    assert out == "arn:aws:iam::100000000000:role/track1-cicd-deploy-role"


def test_same_real_account_id_maps_to_same_placeholder():
    s = GraphSanitizer()
    a = s.sanitize_text("arn:aws:iam::123456789012:role/role-a")
    b = s.sanitize_text("arn:aws:iam::123456789012:role/role-b")
    assert a.split(":")[4] == b.split(":")[4]  # same placeholder account segment


def test_different_real_account_ids_get_different_placeholders():
    s = GraphSanitizer()
    a = s.sanitize_text("arn:aws:iam::123456789012:role/x")
    b = s.sanitize_text("arn:aws:iam::999988887777:role/x")
    assert a != b
    assert "123456789012" not in a and "999988887777" not in b


def test_gcp_project_id_in_resource_path_masked():
    s = GraphSanitizer()
    out = s.sanitize_text("projects/iam-pathfinder-sandbox/serviceAccounts/track1-owner-sa@x.iam.gserviceaccount.com")
    assert "iam-pathfinder-sandbox" not in out
    assert out.startswith("projects/sanitized-gcp-project-1/")


def test_gcp_sa_email_domain_masked_short_name_preserved():
    s = GraphSanitizer()
    out = s.sanitize_text("track1-owner-sa@iam-pathfinder-sandbox.iam.gserviceaccount.com")
    assert out.startswith("track1-owner-sa@sanitized-gcp-project-1")
    assert "iam-pathfinder-sandbox" not in out


def test_project_id_consistent_across_path_and_email_in_same_string():
    s = GraphSanitizer()
    text = (
        "projects/iam-pathfinder-sandbox/serviceAccounts/"
        "track1-owner-sa@iam-pathfinder-sandbox.iam.gserviceaccount.com"
    )
    out = s.sanitize_text(text)
    path_placeholder = out.split("/")[1]
    email_placeholder = out.split("@")[1].split(".")[0]
    assert path_placeholder == email_placeholder


def test_role_and_service_account_names_left_untouched():
    """SCOPE.md rule 5 names account IDs/ARNs/project IDs specifically --
    descriptive resource names are meant to stay visible in the case study."""
    s = GraphSanitizer()
    out = s.sanitize_text("arn:aws:iam::123456789012:role/track1-cicd-deploy-role")
    assert "track1-cicd-deploy-role" in out


def test_non_identifying_text_passes_through_unchanged():
    s = GraphSanitizer()
    assert s.sanitize_text("token.actions.githubusercontent.com") == "token.actions.githubusercontent.com"
    assert s.sanitize_text(None) is None
    assert s.sanitize_text("") == ""


def test_sanitize_graph_preserves_referential_integrity():
    bridge = Node(
        id="cross_cloud:oidc_bridge:token.actions.githubusercontent.com",
        type=NodeType.APP_REGISTRATION,
        cloud=Cloud.CROSS_CLOUD,
        name="token.actions.githubusercontent.com",
    )
    role = Node(
        id="aws:role:arn:aws:iam::123456789012:role/track1-cicd-deploy-role",
        type=NodeType.ROLE,
        cloud=Cloud.AWS,
        name="track1-cicd-deploy-role",
        attributes={"arn": "arn:aws:iam::123456789012:role/track1-cicd-deploy-role"},
    )
    edge = Edge(source=bridge.id, target=role.id, type=EdgeType.FEDERATES_WITH, cloud=Cloud.CROSS_CLOUD)

    new_nodes, new_edges, _sanitizer = sanitize_graph([bridge, role], [edge])
    node_ids = {n.id for n in new_nodes}
    assert new_edges[0].source in node_ids
    assert new_edges[0].target in node_ids
    assert "123456789012" not in new_edges[0].target


def test_sanitize_graph_masks_node_attributes():
    node = Node(
        id="aws:role:arn:aws:iam::123456789012:role/x",
        type=NodeType.ROLE,
        cloud=Cloud.AWS,
        name="x",
        attributes={"arn": "arn:aws:iam::123456789012:role/x", "created": "2026-01-01"},
    )
    new_nodes, _new_edges, _sanitizer = sanitize_graph([node], [])
    assert "123456789012" not in new_nodes[0].attributes["arn"]
    assert new_nodes[0].attributes["created"] == "2026-01-01"  # untouched, not identifying


def test_sanitize_graph_masks_list_attributes():
    """merged_from (correlation.py's bridge-merge bookkeeping) is a list of
    the OLD pre-merge node ids, which embed the same real identifiers."""
    node = Node(
        id="cross_cloud:oidc_bridge:x",
        type=NodeType.APP_REGISTRATION,
        cloud=Cloud.CROSS_CLOUD,
        name="x",
        attributes={
            "merged_from": [
                "federated:arn:aws:iam::123456789012:oidc-provider/x",
                "gcp:wif_bridge:https://x",
            ]
        },
    )
    new_nodes, _new_edges, _sanitizer = sanitize_graph([node], [])
    merged = new_nodes[0].attributes["merged_from"]
    assert not any("123456789012" in v for v in merged)


def test_sanitize_graph_masks_edge_condition_and_evidence():
    edge = Edge(
        source="a",
        target="b",
        type=EdgeType.FEDERATES_WITH,
        cloud=Cloud.CROSS_CLOUD,
        condition='assertion.arn == "arn:aws:iam::123456789012:role/x"',
        evidence="WIF binding on projects/iam-pathfinder-sandbox/locations/global",
    )
    node_a = Node(id="a", type=NodeType.APP_REGISTRATION, cloud=Cloud.CROSS_CLOUD, name="a")
    node_b = Node(id="b", type=NodeType.ROLE, cloud=Cloud.AWS, name="b")

    _new_nodes, new_edges, _sanitizer = sanitize_graph([node_a, node_b], [edge])
    assert "123456789012" not in new_edges[0].condition
    assert "iam-pathfinder-sandbox" not in new_edges[0].evidence


def test_sanitizer_is_shared_within_one_sanitize_graph_call():
    """Two different nodes referencing the same real account must get the
    SAME placeholder -- proves one GraphSanitizer instance is used
    consistently across the whole graph, not one per node."""
    n1 = Node(
        id="aws:role:arn:aws:iam::123456789012:role/a", type=NodeType.ROLE, cloud=Cloud.AWS, name="a",
        attributes={"arn": "arn:aws:iam::123456789012:role/a"},
    )
    n2 = Node(
        id="aws:role:arn:aws:iam::123456789012:role/b", type=NodeType.ROLE, cloud=Cloud.AWS, name="b",
        attributes={"arn": "arn:aws:iam::123456789012:role/b"},
    )
    new_nodes, _edges, _sanitizer = sanitize_graph([n1, n2], [])
    placeholder_1 = new_nodes[0].attributes["arn"].split(":")[4]
    placeholder_2 = new_nodes[1].attributes["arn"].split(":")[4]
    assert placeholder_1 == placeholder_2
