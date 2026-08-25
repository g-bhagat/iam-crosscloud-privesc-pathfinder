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
    """Pattern 3 is no longer deferred -- it shares pattern 2's rule
    function (direction-aware), so only 4 and 5 remain genuinely
    unimplemented."""
    nodes, edges = sample_graph
    merged_nodes, merged_edges, _ = correlate(nodes, edges)
    result = run_all(merged_nodes, merged_edges)

    deferred_ids = {p[0] for p in result.skipped_patterns}
    assert deferred_ids == {4, 5}
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


def test_pattern3_flags_mirror_direction_direct_medium_confidence_admin_edge():
    """Mirror of test_pattern2_*, opposite trust direction: a direct
    GCP->AWS FEDERATES_WITH edge, account-level scoped only, into an
    is_admin AWS node. Same underlying rule function as pattern 2 --
    check_pattern2_gcp_wif_overbroad_aws_trust's matching logic only keys
    off source.cloud != target.cloud, not which specific cloud is which --
    so this fires with zero code changes to the matching logic itself; the
    only thing under test here is that the emitted Finding is correctly
    labeled pattern_id=3, not still pattern_id=2."""
    from src.graph_schema import Cloud, Edge, EdgeType, Node, NodeType

    gcp_source = Node(
        id="gcp:service_account:ci@p.iam.gserviceaccount.com",
        type=NodeType.SERVICE_ACCOUNT, cloud=Cloud.GCP, name="ci-sa",
    )
    aws_admin = Node(
        id="aws:role:arn:aws:iam::1:role/admin-role",
        type=NodeType.ROLE, cloud=Cloud.AWS, name="admin-role", is_admin=True,
    )
    nodes = [gcp_source, aws_admin]
    edges = [
        Edge(
            source=gcp_source.id,
            target=aws_admin.id,
            type=EdgeType.FEDERATES_WITH,
            cloud=Cloud.CROSS_CLOUD,
            condition='assertion.account == "1"',
        )
    ]

    merged_nodes, merged_edges, _ = correlate(nodes, edges)
    result = run_all(merged_nodes, merged_edges)

    pattern3 = [f for f in result.findings if f.pattern_id == 3]
    assert len(pattern3) == 1
    assert pattern3[0].target_node == aws_admin.id
    assert pattern3[0].pattern_name == "Overly-broad AWS trust of a GCP principal"
    # And it must NOT also (or instead) show up mislabeled as pattern 2.
    assert not any(f.pattern_id == 2 for f in result.findings)
