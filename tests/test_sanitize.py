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


def test_aws_external_account_node_id_masked():
    """GCPCollector's synthetic Track 2 node id -- an AWS account ID
    appearing outside an ARN entirely, so _AWS_ARN_ACCOUNT_RE alone
    doesn't cover it."""
    s = GraphSanitizer()
    out = s.sanitize_text("aws:external_account:999988887777")
    assert "999988887777" not in out
    assert out == "aws:external_account:100000000000"


def test_aws_account_id_in_node_name_phrase_masked():
    s = GraphSanitizer()
    out = s.sanitize_text("any AWS principal in account 999988887777")
    assert "999988887777" not in out
    assert out == "any AWS principal in account 100000000000"


def test_aws_account_id_bare_attribute_value_masked():
    """attributes["aws_account_id"] on GCPCollector's Track 2 node/edge is
    the account ID with no wrapping text at all -- the narrowest, most
    false-positive-prone shape, so it's fully anchored (whole-string
    match only), not a blanket embedded-digits search."""
    s = GraphSanitizer()
    out = s.sanitize_text("999988887777")
    assert out != "999988887777"
    assert out == "100000000000"


def test_aws_external_account_id_consistent_with_arn_elsewhere_in_same_graph():
    """The same real account referenced both as a synthetic Track 2 node
    and as a real ARN elsewhere in the graph must map to the SAME
    placeholder -- proves both shapes share _aws_account_placeholder."""
    s = GraphSanitizer()
    from_node_id = s.sanitize_text("aws:external_account:999988887777")
    from_arn = s.sanitize_text("arn:aws:iam::999988887777:role/some-role")
    assert from_node_id.split(":")[-1] == from_arn.split(":")[4]


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


def test_human_email_masked():
    """A bare human user email (e.g. a NodeType.USER node's name/id) must
    be masked too -- not just GCP SA emails. Mirrors
    test_gcp_sa_email_domain_masked_short_name_preserved, but unlike the
    SA case, the local part is itself identifying (a real person), so the
    whole address is replaced rather than partially preserved."""
    s = GraphSanitizer()
    out = s.sanitize_text("gopilalbhagat9@gmail.com")
    assert out != "gopilalbhagat9@gmail.com"
    assert "gopilalbhagat9" not in out
    assert "gmail.com" not in out
    assert out == "sanitized-user-1@example.com"


def test_same_human_email_maps_to_same_placeholder():
    s = GraphSanitizer()
    first = s.sanitize_text("alice@example.org")
    second = s.sanitize_text("alice@example.org")
    assert first == second


def test_different_human_emails_get_different_placeholders():
    s = GraphSanitizer()
    a = s.sanitize_text("alice@example.org")
    b = s.sanitize_text("bob@example.org")
    assert a != b


def test_human_email_regex_does_not_reprocess_already_sanitized_gcp_sa_email():
    """The human-email pattern runs after the GCP-SA-email pattern and
    must not re-mask its output -- otherwise the SA's short name
    (deliberately preserved by the SA-specific rule) would be destroyed
    too."""
    s = GraphSanitizer()
    out = s.sanitize_text("track1-owner-sa@iam-pathfinder-sandbox.iam.gserviceaccount.com")
    assert out.startswith("track1-owner-sa@sanitized-gcp-project-1")
    assert out.endswith(".iam.gserviceaccount.com")


def test_human_email_inside_gcp_user_node_id_masked():
    """gcp:user:<email> is the real node.id shape GCPCollector._member_to_node
    produces for a `user:` IAM binding member."""
    s = GraphSanitizer()
    out = s.sanitize_text("gcp:user:alice@example.org")
    assert out.startswith("gcp:user:")
    assert "alice@example.org" not in out


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


def test_sanitize_graph_masks_gcp_collector_track2_synthetic_node():
    """End-to-end through sanitize_node/sanitize_graph (not just raw
    sanitize_text) for the exact node shape GCPCollector's Track 2 fix
    produces: id, name, AND the bare aws_account_id attribute all embed
    the real account ID and must all come out masked, consistently."""
    node = Node(
        id="aws:external_account:999988887777",
        type=NodeType.USER,
        cloud=Cloud.AWS,
        name="any AWS principal in account 999988887777",
        external_facing=True,
        attributes={"aws_account_id": "999988887777"},
    )
    new_nodes, _new_edges, _sanitizer = sanitize_graph([node], [])
    sanitized = new_nodes[0]
    assert "999988887777" not in sanitized.id
    assert "999988887777" not in sanitized.name
    assert "999988887777" not in sanitized.attributes["aws_account_id"]
    # All three must resolve to the SAME placeholder account.
    node_id_placeholder = sanitized.id.split(":")[-1]
    assert node_id_placeholder in sanitized.name
    assert sanitized.attributes["aws_account_id"] == node_id_placeholder


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
