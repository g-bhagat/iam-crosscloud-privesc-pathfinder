from src.analysis.correlation import correlate
from src.analysis.escalation_rules import DEFERRED_PATTERNS, run_all


def test_pattern1_true_positive_on_loose_wif_provider(sample_graph):
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)
    result = run_all(merged_nodes, merged_edges)

    pattern1_findings = [f for f in result.findings if f.pattern_id == 1]
    assert len(pattern1_findings) == 1
    finding = pattern1_findings[0]
    assert "track1-owner-sa" in finding.target_node


def test_pattern1_true_negative_on_scoped_control(sample_graph):
    """The correctly-scoped negative-control binding (task 18) must
    NEVER appear as a finding target -- this is SCOPE.md's core success
    criterion: prove a true negative, not just a true positive."""
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)
    result = run_all(merged_nodes, merged_edges)

    assert not any("track1-scoped-sa" in f.target_node for f in result.findings)


def test_correctly_scoped_aws_role_is_not_flagged(sample_graph):
    """The AWS role (correctly scoped, and not privileged) must not be
    flagged even though it IS reached via the same bridge."""
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)
    result = run_all(merged_nodes, merged_edges)

    assert not any("cicd-deploy-role" in f.target_node for f in result.findings)


def test_unreachable_admin_node_is_never_a_finding_target(sample_graph):
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)
    result = run_all(merged_nodes, merged_edges)

    assert not any("legacy-break-glass" in f.target_node for f in result.findings)


def test_deferred_patterns_are_reported_not_silently_dropped(sample_graph):
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)
    result = run_all(merged_nodes, merged_edges)

    deferred_ids = {p[0] for p in result.skipped_patterns}
    assert deferred_ids == {3, 4, 5}
    assert deferred_ids == {p[0] for p in DEFERRED_PATTERNS}


def test_pattern2_flags_direct_medium_confidence_cross_cloud_admin_edge():
    """Synthetic Track-2-shaped case (no live sandbox infra yet): a direct
    AWS->GCP FEDERATES_WITH edge, account-level scoped only, into an
    is_admin GCP node."""
    from src.graph_schema import Cloud, Edge, EdgeType, Node, NodeType

    aws_source = Node(id="aws:role:arn:aws:iam::1:role/any-role", type=NodeType.ROLE, cloud=Cloud.AWS, name="any-role")
    gcp_admin = Node(id="gcp:service_account:owner@p.iam.gserviceaccount.com", type=NodeType.SERVICE_ACCOUNT, cloud=Cloud.GCP, name="owner-sa", is_admin=True)
    nodes = [aws_source, gcp_admin]
    edges = [
        Edge(
            source=aws_source.id,
            target=gcp_admin.id,
            type=EdgeType.FEDERATES_WITH,
            cloud=Cloud.CROSS_CLOUD,
            condition='assertion.account == "1"',
        )
    ]

    merged_nodes, merged_edges, _ = correlate(nodes, edges)
    result = run_all(merged_nodes, merged_edges)

    pattern2 = [f for f in result.findings if f.pattern_id == 2]
    assert len(pattern2) == 1
    assert pattern2[0].target_node == gcp_admin.id
