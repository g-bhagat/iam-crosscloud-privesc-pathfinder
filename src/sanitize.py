"""
sanitize.py

Masks the real, identifying values SCOPE.md rule 5 forbids in anything
committed or published: AWS account IDs (and the ARNs that embed them),
GCP project IDs/numbers (and the resource paths / service-account
emails that embed them), and human user email addresses (a bare
NodeType.USER node's name/id, e.g. an IAM user provisioned by email
rather than username). Not applied automatically anywhere -- a raw
graph is still useful for the analyst's own local inspection, and
`AWSCollector`/`GCPCollector`/`correlation.py` all produce raw output on
purpose. Callers opt in explicitly: `pyvis_export.export_graph(...,
sanitize=True)`, or `scripts/run_detector.py`'s `--output` check (forced
on automatically once the output path resolves under `docs/`).

Scope, deliberately narrow: this masks exactly the four identifier
classes that are either named by SCOPE.md rule 5 (account IDs, ARNs,
project IDs) or are themselves a real person's PII incidentally swept
up by graph collection (human email addresses). It does NOT attempt to
also guess-mask resource/role/SA names, GitHub org/repo names, or
anything else outside those four -- those are generally meant to stay
visible (they're the descriptive labels the case study narrative
depends on), and a broader heuristic would have a much higher
false-positive rate. If a future export needs to hide something else,
that's a deliberate scope change to this module, not an oversight.

Approach: deterministic, run-local pseudonymization via regex matched
against the *structural* patterns these values actually appear in (an
ARN's account-ID field, GCPCollector's `aws:external_account:<id>`
synthetic-node id and its "account <id>" node name -- see
gcp_collector.py's Track 2 fix -- a `projects/<id>/` path segment, a
`...@<project>.iam.gserviceaccount.com` email domain, a bare
`local@domain` email) -- not a blanket "looks like a long alphanumeric
token" guess, which would false-positive on ordinary resource names.
The human-email pattern runs last and explicitly skips anything already
ending in `.iam.gserviceaccount.com`, so it never re-masks output the
GCP-SA-email pattern already produced. The same real value maps to the
same placeholder everywhere it appears within one `sanitize_graph()`
call, so a sanitized graph stays internally consistent (the same AWS
account still looks like the same account throughout, edges still
connect to the right nodes) -- but the specific placeholder chosen is
NOT guaranteed stable across separate calls/runs. This is masking for
publication, not cryptographic anonymization; treat a "sanitized"
export as fit for sharing, not as a security boundary in its own right.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from .graph_schema import Edge, Node

_AWS_ARN_ACCOUNT_RE = re.compile(r"(arn:aws[a-z0-9-]*:[a-z0-9-]+:[a-z0-9-]*:)(\d{12})(:)")
# GCPCollector's synthetic "any AWS principal in this account" node/edge
# shapes (see gcp_collector.py's _emit_workload_identity_edge, Track 2's
# AWS-type-provider fix) -- an AWS account ID appearing outside an ARN
# entirely, so it needs its own structural patterns rather than reusing
# _AWS_ARN_ACCOUNT_RE. Three shapes, in increasing order of how little
# context surrounds the digits: the node id's "aws:external_account:"
# prefix, the node name's "...account <id>" phrasing, and the bare
# attributes["aws_account_id"] value (nothing but the 12 digits, hence
# fully anchored -- deliberately NOT a blanket embedded-digits search,
# which would risk false-positiving on an unrelated 12-digit number
# elsewhere in some other attribute).
_AWS_EXTERNAL_ACCOUNT_NODE_RE = re.compile(r"(aws:external_account:)(\d{12})")
_AWS_ACCOUNT_ID_IN_PHRASE_RE = re.compile(r"(\baccount )(\d{12})\b")
_AWS_ACCOUNT_ID_BARE_RE = re.compile(r"^(\d{12})$")
_GCP_PROJECT_PATH_RE = re.compile(r"(projects/)([a-zA-Z0-9][a-zA-Z0-9-]{3,29})(?=/|$)")
_GCP_SA_EMAIL_RE = re.compile(r"([a-zA-Z0-9-]+)@([a-zA-Z0-9-]+)\.iam\.gserviceaccount\.com")
# General "local@domain.tld" shape, for a plain human user email (a
# NodeType.USER node provisioned by email rather than username -- see
# GCPCollector._member_to_node's `user:` branch, and AWS IAM users can be
# named by email too). Deliberately broader/less structural than the
# three patterns above, because a human email has no cloud-specific
# resource-path wrapper to key off of -- it's just an email. Matched
# LAST, after _GCP_SA_EMAIL_RE has already run, so by the time this regex
# sees the text any real GCP SA email has already become
# `name@sanitized-gcp-project-N.iam.gserviceaccount.com`; the substitution
# callback explicitly skips anything still ending in
# `.iam.gserviceaccount.com` so it never re-masks (and thereby corrupts)
# that already-sanitized output.
_HUMAN_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


class GraphSanitizer:
    """Stateful pseudonymizer -- one instance per sanitize_graph() call, so
    every node/edge it touches shares the same real-value -> placeholder
    mapping."""

    def __init__(self):
        self._aws_accounts: dict[str, str] = {}
        self._gcp_projects: dict[str, str] = {}
        self._human_emails: dict[str, str] = {}

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

    def _human_email_placeholder(self, real: str) -> str:
        if real not in self._human_emails:
            # Unlike the GCP SA email pattern, the local part of a human
            # email IS the identifying info (a real person's name/handle),
            # so it's replaced wholesale rather than partially preserved --
            # example.com is IANA-reserved for exactly this documentation
            # use, never a real deliverable domain.
            self._human_emails[real] = f"sanitized-user-{len(self._human_emails) + 1}@example.com"
        return self._human_emails[real]

    def _sanitize_human_email(self, match: re.Match[str]) -> str:
        email = match.group(0)
        if email.lower().endswith(".iam.gserviceaccount.com"):
            # Already handled (and rewritten) by _GCP_SA_EMAIL_RE above --
            # leave the sanitized SA email alone rather than masking it a
            # second time.
            return email
        return self._human_email_placeholder(email)

    def sanitize_text(self, text: str | None) -> str | None:
        if not text:
            return text
        text = _AWS_ARN_ACCOUNT_RE.sub(
            lambda m: m.group(1) + self._aws_account_placeholder(m.group(2)) + m.group(3), text
        )
        text = _AWS_EXTERNAL_ACCOUNT_NODE_RE.sub(
            lambda m: m.group(1) + self._aws_account_placeholder(m.group(2)), text
        )
        text = _AWS_ACCOUNT_ID_IN_PHRASE_RE.sub(
            lambda m: m.group(1) + self._aws_account_placeholder(m.group(2)), text
        )
        text = _AWS_ACCOUNT_ID_BARE_RE.sub(lambda m: self._aws_account_placeholder(m.group(1)), text)
        text = _GCP_PROJECT_PATH_RE.sub(lambda m: m.group(1) + self._gcp_project_placeholder(m.group(2)), text)
        text = _GCP_SA_EMAIL_RE.sub(
            lambda m: f"{m.group(1)}@{self._gcp_project_placeholder(m.group(2))}.iam.gserviceaccount.com", text
        )
        text = _HUMAN_EMAIL_RE.sub(self._sanitize_human_email, text)
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
