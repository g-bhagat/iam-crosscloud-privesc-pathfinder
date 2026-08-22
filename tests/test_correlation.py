from src.analysis.confidence import Confidence
from src.analysis.correlation import (
    correlate,
    merge_direct_references,
    merge_oidc_bridges,
)
from src.graph_schema import Cloud, Edge, EdgeType, Node, NodeType


def test_oidc_bridges_merge_into_one_canonical_node(sample_graph):
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)

    bridge_nodes = [n for n in merged_nodes if n.id.startswith("cross_cloud:oidc_bridge:")]
    assert len(bridge_nodes) == 1
    canonical = bridge_nodes[0]
    assert canonical.name == "token.actions.githubusercontent.com"

    # The old per-cloud bridge node ids must be gone.
    assert not any(n.id.startswith("federated:") for n in merged_nodes)
    assert not any(n.id.startswith("gcp:wif_bridge:") for n in merged_nodes)

    # All three FEDERATES_WITH edges (AWS role, GCP owner SA, GCP scoped SA)
    # now originate from the single canonical node.
    federates = [e for e in merged_edges if e.type == EdgeType.FEDERATES_WITH]
    assert len(federates) == 3
    assert all(e.source == canonical.id for e in federates)


def test_confidence_tiers_assigned_correctly(sample_graph):
    nodes, edges = sample_graph
    _, merged_edges, _ = correlate(nodes, edges)

    by_target = {e.target: e for e in merged_edges if e.type == EdgeType.FEDERATES_WITH}

    aws_role_id = next(t for t in by_target if t.startswith("aws:role:") and "cicd-deploy" in t)
    owner_sa_id = next(t for t in by_target if "track1-owner-sa" in t)
    scoped_sa_id = next(t for t in by_target if "track1-scoped-sa" in t)

    assert by_target[aws_role_id].attributes["confidence"] == Confidence.HIGH.value
    assert by_target[owner_sa_id].attributes["confidence"] == Confidence.MEDIUM.value
    assert by_target[scoped_sa_id].attributes["confidence"] == Confidence.HIGH.value


def test_low_confidence_edges_excluded_and_reported_as_advisory():
    bridge = Node(id="federated:arn:aws:iam::123456789012:oidc-provider/example.com", type=NodeType.APP_REGISTRATION, cloud=Cloud.CROSS_CLOUD, name="arn:aws:iam::123456789012:oidc-provider/example.com", external_facing=True)
    target = Node(id="aws:role:x", type=NodeType.ROLE, cloud=Cloud.AWS, name="x")
    nodes = [bridge, target]
    edges = [Edge(source=bridge.id, target=target.id, type=EdgeType.FEDERATES_WITH, cloud=Cloud.CROSS_CLOUD, condition=None)]

    _merged_nodes, merged_edges, advisories = correlate(nodes, edges)

    assert merged_edges == []
    assert len(advisories) == 1
    assert advisories[0].node_a == bridge.id


def test_non_federation_edges_pass_through_unchanged(sample_graph):
    nodes, edges = sample_graph
    _, merged_edges, _ = correlate(nodes, edges)
    member_of = [e for e in merged_edges if e.type == EdgeType.MEMBER_OF]
    assert len(member_of) == 1


def test_direct_reference_merge_resolves_embedded_arn():
    """Synthetic Track-2-shaped exercise: a GCP WIF edge whose condition
    embeds a literal AWS role ARN should get its target rewritten straight
    to that AWS role node -- no third-party bridge involved."""
    aws_role = Node(
        id="aws:role:arn:aws:iam::999988887777:role/data-pipeline-role",
        type=NodeType.ROLE,
        cloud=Cloud.AWS,
        name="data-pipeline-role",
        attributes={"arn": "arn:aws:iam::999988887777:role/data-pipeline-role"},
    )
    gcp_source = Node(
        id="gcp:wif_provider:aws-principal-pool",
        type=NodeType.APP_REGISTRATION,
        cloud=Cloud.GCP,
        name="aws-principal-pool",
    )
    placeholder_target = Node(id="unresolved:aws-role-ref", type=NodeType.ROLE, cloud=Cloud.AWS, name="unresolved")

    nodes = {n.id: n for n in [aws_role, gcp_source, placeholder_target]}
    edges = [
        Edge(
            source=gcp_source.id,
            target=placeholder_target.id,
            type=EdgeType.FEDERATES_WITH,
            cloud=Cloud.CROSS_CLOUD,
            condition='assertion.arn == "arn:aws:iam::999988887777:role/data-pipeline-role"',
        )
    ]

    resolved = merge_direct_references(nodes, edges)
    assert resolved[0].target == aws_role.id


def test_merge_oidc_bridges_is_noop_when_only_one_cloud_saw_issuer():
    bridge = Node(id="federated:arn:aws:iam::1:oidc-provider/only-one-side.example.com", type=NodeType.APP_REGISTRATION, cloud=Cloud.CROSS_CLOUD, name="arn:aws:iam::1:oidc-provider/only-one-side.example.com")
    target = Node(id="aws:role:y", type=NodeType.ROLE, cloud=Cloud.AWS, name="y")
    nodes = {n.id: n for n in [bridge, target]}
    edges = [Edge(source=bridge.id, target=target.id, type=EdgeType.FEDERATES_WITH, cloud=Cloud.CROSS_CLOUD)]

    merged_nodes, merged_edges = merge_oidc_bridges(nodes, edges)
    assert bridge.id in merged_nodes  # untouched, nothing to merge with
    assert merged_edges[0].source == bridge.id
