"""
The scope-boundary annotation ("this graph shows escalation-relevant
capabilities only, not a full IAM inventory") must be visible on the
rendered artifact itself, not just documented in source comments -- an
analyst screenshotting this for the portfolio site, or handing the HTML
to someone else, loses the source-code context otherwise.
"""

from src.graph_schema import Cloud, Node, NodeType
from src.visualization.pyvis_export import (
    SCOPE_BOUNDARY_NOTE,
    _inject_scope_boundary_annotation,
    export_graph,
)


def test_inject_scope_boundary_annotation_adds_note_before_body_close():
    html = "<html><body><p>graph</p></body></html>"
    out = _inject_scope_boundary_annotation(html)
    assert SCOPE_BOUNDARY_NOTE in out
    assert out.index(SCOPE_BOUNDARY_NOTE) < out.index("</body>")


def test_inject_scope_boundary_annotation_is_fixed_positioned():
    html = "<html><body></body></html>"
    out = _inject_scope_boundary_annotation(html)
    assert "position: fixed" in out


def test_inject_scope_boundary_annotation_falls_back_without_body_tag():
    """Defensive: even if the template ever changes shape, the note must
    still make it into the output rather than silently vanishing."""
    html = "<html>no body tag here</html>"
    out = _inject_scope_boundary_annotation(html)
    assert SCOPE_BOUNDARY_NOTE in out


def test_export_graph_includes_scope_note_by_default(tmp_path):
    node = Node(id="a", type=NodeType.ROLE, cloud=Cloud.AWS, name="a")
    out = export_graph([node], [], tmp_path / "graph.html")
    html = out.read_text()
    assert "not a complete IAM permissions inventory" in html
    assert "S3 read/write" in html


def test_export_graph_scope_note_appears_exactly_once(tmp_path):
    node = Node(id="a", type=NodeType.ROLE, cloud=Cloud.AWS, name="a")
    out = export_graph([node], [], tmp_path / "graph.html")
    assert out.read_text().count("Scope note:") == 1


def test_export_graph_scope_note_present_with_sanitize_true(tmp_path):
    """The annotation is a static string, not derived from graph data --
    confirm it survives the sanitize=True code path too, not just the
    default one."""
    node = Node(id="a", type=NodeType.ROLE, cloud=Cloud.AWS, name="a")
    out = export_graph([node], [], tmp_path / "graph.html", sanitize=True)
    assert "not a complete IAM permissions inventory" in out.read_text()
