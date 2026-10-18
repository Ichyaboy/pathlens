import json
from pathlib import Path
import networkx as nx
import pytest
from pydantic import ValidationError
from pathlens.cli import GraphData

SAMPLE = Path(__file__).resolve().parents[1] / "data" / "sample_domain.json"

def test_sample_path():
    data = GraphData.model_validate(json.loads(SAMPLE.read_text()))
    graph = nx.DiGraph((edge.source, edge.target) for edge in data.edges)
    assert nx.shortest_path(graph, "ICHYABOY", "DOMAIN ADMINS") == ["ICHYABOY", "HELPDESK", "IT-ADMINS", "DOMAIN ADMINS"]

def test_reject_unknown_node():
    with pytest.raises(ValidationError):
        GraphData.model_validate({"nodes": [{"id": "A", "type": "User"}], "edges": [{"source": "A", "target": "B", "relation": "MemberOf"}]})

def test_direction_matters():
    data = GraphData.model_validate(json.loads(SAMPLE.read_text()))
    graph = nx.DiGraph((edge.source, edge.target) for edge in data.edges)
    with pytest.raises(nx.NetworkXNoPath):
        nx.shortest_path(graph, "DOMAIN ADMINS", "ICHYABOY")
