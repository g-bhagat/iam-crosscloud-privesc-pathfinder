import json
from pathlib import Path

import pytest

from src.graph_schema import Edge, Node

SAMPLE_GRAPH_PATH = Path(__file__).resolve().parent.parent / "sample_data" / "sample_graph.json"


@pytest.fixture
def sample_graph() -> tuple[list[Node], list[Edge]]:
    data = json.loads(SAMPLE_GRAPH_PATH.read_text())
    nodes = [Node.from_dict(n) for n in data["nodes"]]
    edges = [Edge.from_dict(e) for e in data["edges"]]
    return nodes, edges
