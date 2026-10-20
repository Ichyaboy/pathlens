import json
from pathlib import Path
import networkx as nx
import pytest
from pydantic import ValidationError
from itertools import permutations

from pathlens.graph import GraphData, analyze_graph, build_graph, shortest_node_path

SAMPLE = Path(__file__).resolve().parents[1] / "data" / "sample_domain.json"

def test_sample_path():
    data = GraphData.model_validate(json.loads(SAMPLE.read_text()))
    graph = build_graph(data)
    assert isinstance(graph, nx.MultiDiGraph)
    assert shortest_node_path(graph, "ICHYABOY", "DOMAIN ADMINS") == ["ICHYABOY", "HELPDESK", "IT-ADMINS", "DOMAIN ADMINS"]
    result = analyze_graph(graph, "ICHYABOY", "DOMAIN ADMINS")
    assert [hop[0].edge.relation for hop in result.relationships] == [
        "MemberOf", "GenericAll", "MemberOf",
    ]

def test_reject_unknown_node():
    with pytest.raises(ValidationError):
        GraphData.model_validate({"nodes": [{"id": "A", "type": "User"}], "edges": [{"source": "A", "target": "B", "relation": "MemberOf"}]})

def test_direction_matters():
    data = GraphData.model_validate(json.loads(SAMPLE.read_text()))
    graph = build_graph(data)
    with pytest.raises(nx.NetworkXNoPath):
        shortest_node_path(graph, "DOMAIN ADMINS", "ICHYABOY")


def make_data(ids, edges, **metadata):
    return GraphData.model_validate({
        "nodes": [{"id": node, "type": "Group"} for node in ids],
        "edges": [
            {"source": start, "target": end, "relation": relation}
            for start, end, relation in edges
        ],
        **metadata,
    })


def test_parallel_relationships_include_duplicates_and_unknowns():
    data = make_data(["A", "B"], [
        ("A", "B", "UnknownPermission"),
        ("A", "B", "MemberOf"),
        ("A", "B", "MemberOf"),
        ("B", "A", "GenericAll"),
    ])
    graph = build_graph(data)
    assert graph.number_of_edges() == 4
    reports = analyze_graph(graph, "A", "B").relationships[0]
    assert [r.edge.relation for r in reports] == [
        "MemberOf", "MemberOf", "UnknownPermission",
    ]
    assert reports[0].recognized
    assert not reports[-1].recognized
    assert reports[-1].explanation == (
        "Unrecognized relationship; no security conclusion available."
    )
    assert analyze_graph(graph, "B", "A").relationships[0][0].edge.relation == "GenericAll"


def test_shortest_path_is_independent_of_node_and_edge_order():
    edges = [
        ("S", "a", "MemberOf"), ("a", "T", "MemberOf"),
        ("S", "B", "MemberOf"), ("B", "T", "MemberOf"),
    ]
    # Exhaust all input orders, including a case-sensitive tie.
    for nodes in permutations(["S", "a", "B", "T"]):
        for reordered in permutations(edges):
            graph = build_graph(make_data(nodes, reordered))
            assert shortest_node_path(graph, "S", "T") == ["S", "B", "T"]


def test_hops_take_priority_over_lexicographic_order_and_cycles():
    graph = build_graph(make_data(["S", "A", "B", "T"], [
        ("S", "A", "MemberOf"), ("A", "B", "MemberOf"),
        ("B", "S", "MemberOf"), ("B", "T", "MemberOf"),
        ("S", "T", "MemberOf"),
    ]))
    assert shortest_node_path(graph, "S", "T") == ["S", "T"]


def test_metadata_round_trip_and_stable_parallel_order():
    raw = {
        "evidence": {"dataset": ["synthetic", 1, False]},
        "provenance": "test fixture",
        "nodes": [
            {"id": "A", "type": "User", "evidence": None,
             "provenance": {"original_id": "user-1"}},
            {"id": "B", "type": "Group", "evidence": []},
        ],
        "edges": [
            {"source": "A", "target": "B", "relation": "MemberOf",
             "evidence": {"record": record}, "provenance": ["fixture", record]}
            for record in [2, 1]
        ],
    }
    data = GraphData.model_validate(raw)
    assert data.model_dump(exclude_unset=True) == raw
    graph = build_graph(data)
    result = analyze_graph(graph, "A", "B")
    assert result.metadata == {key: raw[key] for key in ("evidence", "provenance")}
    assert [n.model_dump(exclude_unset=True) for n in result.nodes] == raw["nodes"]
    assert [r.edge.model_dump(exclude_unset=True) for r in result.relationships[0]] == raw["edges"][::-1]
    assert graph.nodes["A"]["provenance"] == raw["nodes"][0]["provenance"]
    assert graph["A"]["B"][0]["evidence"] == {"record": 2}
    reordered = {**raw, "nodes": raw["nodes"][::-1], "edges": raw["edges"][::-1]}
    assert analyze_graph(build_graph(GraphData.model_validate(reordered)), "A", "B") == result
    # Results and the constructed graph must not alias the validated input.
    result.nodes[0].provenance["original_id"] = "changed"
    result.relationships[0][0].edge.evidence["record"] = 99
    assert graph.nodes["A"]["provenance"]["original_id"] == "user-1"
    assert graph["A"]["B"][1]["evidence"]["record"] == 1
    assert data.model_dump(exclude_unset=True) == raw


def test_missing_metadata_is_not_invented():
    graph = build_graph(make_data(["A", "B"], [("A", "B", "MemberOf")]))
    result = analyze_graph(graph, "A", "B")
    assert result.metadata == {}
    for record in [*result.nodes, result.relationships[0][0].edge]:
        assert "evidence" not in record.model_dump(exclude_unset=True)
        assert "provenance" not in record.model_dump(exclude_unset=True)


def test_disconnected_unknown_and_same_node():
    graph = build_graph(make_data(["A", "B"], []))
    with pytest.raises(nx.NetworkXNoPath):
        analyze_graph(graph, "A", "B")
    with pytest.raises(nx.NodeNotFound):
        analyze_graph(graph, "missing", "B")
    result = analyze_graph(graph, "A", "A")
    assert [node.id for node in result.nodes] == ["A"]
    assert result.relationships == []


def test_duplicate_nodes_rejected():
    with pytest.raises(ValidationError, match="Duplicate node IDs"):
        make_data(["A", "A"], [])


@pytest.mark.parametrize("location", ["graph", "node", "edge"])
def test_unknown_fields_are_not_silently_discarded(location):
    raw = make_data(["A", "B"], [("A", "B", "MemberOf")]).model_dump(exclude_unset=True)
    record = raw if location == "graph" else raw["nodes" if location == "node" else "edges"][0]
    record["unsupported_field"] = "value"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        GraphData.model_validate(raw)


def test_nonfinite_metadata_rejected():
    with pytest.raises(ValidationError):
        make_data(["A"], [], evidence=float("nan"))


def test_deep_tie_uses_complete_sequence_not_smallest_immediate_parent():
    edges = [
        ("S", "A", "MemberOf"), ("A", "Z", "MemberOf"),
        ("Z", "M", "MemberOf"), ("S", "B", "MemberOf"),
        ("B", "C", "MemberOf"), ("C", "M", "MemberOf"),
        ("M", "T", "MemberOf"),
    ]
    for ordered in [edges, edges[::-1]]:
        graph = build_graph(make_data(["S", "A", "B", "C", "Z", "M", "T"], ordered))
        assert shortest_node_path(graph, "S", "T") == ["S", "A", "Z", "M", "T"]


def test_many_shortest_paths_do_not_require_enumeration():
    # 2**32 possible shortest paths, but only 66 nodes.
    layers = [["S"]] + [[f"{i:02}a", f"{i:02}b"] for i in range(32)] + [["T"]]
    edges = [(a, b, "MemberOf") for left, right in zip(layers, layers[1:])
             for a in left for b in right]
    graph = build_graph(make_data([n for layer in layers for n in layer], edges[::-1]))
    assert shortest_node_path(graph, "S", "T") == [layer[0] for layer in layers]


def test_graph_level_metadata_is_detached_from_analysis():
    data = make_data(["A"], [], provenance={"records": [1]})
    graph = build_graph(data)
    result = analyze_graph(graph, "A", "A")
    result.metadata["provenance"]["records"].append(2)
    assert graph.graph["provenance"] == {"records": [1]}
    assert data.provenance == {"records": [1]}
