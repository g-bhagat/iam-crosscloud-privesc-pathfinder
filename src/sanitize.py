"""
sanitize.py

Masks the real, identifying values SCOPE.md rule 5 forbids in anything
committed or published: AWS account IDs (and the ARNs that embed them)
and GCP project IDs/numbers (and the resource paths / service-account
emails that embed them). Not applied automatically anywhere -- a raw
graph is still useful for the analyst's own local inspection, and
`AWSCollector`/`GCPCollector`/`correlation.py` all produce raw output on
purpose. Callers opt in explicitly: `pyvis_export.export_graph(...,
sanitize=True)`, or `scripts/run_detector.py`'s `--output` check (forced
on automatically once the output path resolves under `docs/`).

Scope, deliberately narrow: this masks exactly the three identifier
classes SCOPE.md rule 5 names -- account IDs, ARNs, project IDs. It does
NOT attempt to also guess-mask resource/role/SA names, GitHub org/repo
names, or anything else that isn't one of those three -- those are
generally meant to stay visible (they're the descriptive labels the case
study narrative depends on), and a broader heuristic would have a much
higher false-positive rate. If a future export needs to hide something
else, that's a deliberate scope change to this module, not an oversight.

Approach: deterministic, run-local pseudonymization via regex matched
against the *structural* patterns these values actually appear in (an
ARN's account-ID field, a `projects/<id>/` path segment, a
`...@<project>.iam.gserviceaccount.com` email domain) -- not a blanket
"looks like a long alphanumeric token" guess, which would false-positive
on ordinary resource names. The same real value maps to the same
placeholder everywhere it appears within one `sanitize_graph()` call, so
a sanitized graph stays internally consistent (the same AWS account
still looks like the same account throughout, edges still connect to
the right nodes) -- but the specific placeholder chosen is NOT guaranteed
stable across separate calls/runs. This is masking for publication, not
cryptographic anonymization; treat a "sanitized" export as fit for
sharing, not as a security boundary in its own right.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from .graph_schema import Edge, Node

_AWS_ARN_ACCOUNT_RE = re.compile(r"(arn:aws[a-z0-9-]*:[a-z0-9-]+:[a-z0-9-]*:)(\d{12})(:)")
_GCP_PROJECT_PATH_RE = re.compile(r"(projects/)([a-zA-Z0-9][a-zA-Z0-9-]{3,29})(?=/|$)")
_GCP_SA_EMAIL_RE = re.compile(r"([a-zA-Z0-9-]+)@([a-zA-Z0-9-]+)\.iam\.gserviceaccount\.com")


class GraphSanitizer:
    """Stateful pseudonymizer -- one instance per sanitize_graph() call, so
    every node/edge it touches shares the same real-value -> placeholder
    mapping."""

    def __init__(self):
        self._aws_accounts: dict[str, str] = {}
        self._gcp_projects: dict[str, str] = {}

    def _aws_account_placeholder(self, real: str) -> str:
        if real not in self._aws_accounts:
            # 12-digit placeholders, distinguishable from a real account ID
            # only by not being one -- same shape AWS itself uses for its
            # own documentation examples (e.g. 123456789012).
            self._aws_accounts[real] = str(100000000000 + len(self._aws_accounts))
        return self._aws_accounts[real]

    def _gcp_project_placeholder(self, real: str) -> str:
        if real not in self._gcp_projects:
            self._gcp_projects[real] = f"sanitized-gcp-project-{len(self._gcp_projects) + 1}"
        return self._gcp_projects[real]

    def sanitize_text(self, text: str | None) -> str | None:
        if not text:
            return text
        text = _AWS_ARN_ACCOUNT_RE.sub(
            lambda m: m.group(1) + self._aws_account_placeholder(m.group(2)) + m.group(3), text
        )
        text = _GCP_PROJECT_PATH_RE.sub(lambda m: m.group(1) + self._gcp_project_placeholder(m.group(2)), text)
        text = _GCP_SA_EMAIL_RE.sub(
            lambda m: f"{m.group(1)}@{self._gcp_project_placeholder(m.group(2))}.iam.gserviceaccount.com", text
        )
        return text

    def _sanitize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.sanitize_text(value)
        if isinstance(value, list):
            return [self._sanitize_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        return value  # bool/int/float/None etc. -- nothing to mask

    def sanitize_node(self, n: Node) -> Node:
        return replace(
            n,
            id=self.sanitize_text(n.id),
            name=self.sanitize_text(n.name),
            attributes={k: self._sanitize_value(v) for k, v in n.attributes.items()},
        )

    def sanitize_edge(self, e: Edge) -> Edge:
        return replace(
            e,
            source=self.sanitize_text(e.source),
            target=self.sanitize_text(e.target),
            condition=self.sanitize_text(e.condition),
            evidence=self.sanitize_text(e.evidence),
            attributes={k: self._sanitize_value(v) for k, v in e.attributes.items()},
        )


def sanitize_graph(nodes: list[Node], edges: list[Edge]) -> tuple[list[Node], list[Edge], GraphSanitizer]:
    """
    Sanitize a full graph. Returns the new nodes/edges plus the
    GraphSanitizer instance itself, so a caller holding onto other raw
    identifiers computed from the same graph (e.g. pathfinder.py's
    EscalationPath.node_ids, used as a highlight set) can run them through
    `sanitizer.sanitize_text(...)` too and still match up -- node IDs
    change under sanitization (an ARN is part of the ID scheme), so a
    highlight set built before sanitizing won't match node IDs built after
    unless it's translated through the same mapping.
    """
    sanitizer = GraphSanitizer()
    new_nodes = [sanitizer.sanitize_node(n) for n in nodes]
    new_edges = [sanitizer.sanitize_edge(e) for e in edges]
    return new_nodes, new_edges, sanitizer
