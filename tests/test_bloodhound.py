from dataclasses import replace
import hashlib
import json
from pathlib import Path

import networkx as nx
import pytest
from typer.testing import CliRunner

from pathlens.cli import app
from pathlens.graph import GraphData, analyze_graph, build_graph, shortest_node_path
from pathlens.importers.bloodhound import (
    DEFAULT_LIMITS, ImportValidationError, parse_ce_graph, read_ce_graph,
    serialize_graph, write_new_file,
)

FIXTURE = Path(__file__).parent / "fixtures" / "bloodhound" / "ce_graph.json"
runner = CliRunner()


def encoded(document):
    return json.dumps(document).encode()


def minimal():
    return {
        "nodes": {"a": {"kind": "User"}, "b": {"kind": "Group"}},
        "edges": [{"id": "e", "source": "a", "target": "b", "kind": "MemberOf"}],
    }


def test_fixture_topology_and_provenance():
    raw = FIXTURE.read_bytes()
    original = json.loads(raw)
    result = parse_ce_graph(raw)
    graph = build_graph(result.data)
    assert isinstance(graph, nx.MultiDiGraph)
    assert set(graph) == {"bhce:101", "bhce:205", "bhce:999"}
    assert graph.number_of_edges("bhce:101", "bhce:205") == 3
    assert graph.has_edge("bhce:205", "bhce:205")
    assert graph.degree("bhce:999") == 0
    with pytest.raises(nx.NetworkXNoPath):
        shortest_node_path(graph, "bhce:205", "bhce:101")
    for node in result.data.nodes:
        key = node.id.removeprefix("bhce:")
        assert node.provenance["bloodhound"]["record"] == original["nodes"][key]
        assert "evidence" not in node.model_dump(exclude_unset=True)
    for edge in result.data.edges:
        source = edge.provenance["bloodhound"]
        index = int(source["source_location"].split("/")[-1])
        assert source["record"] == original["edges"][index]
        assert "evidence" not in edge.model_dump(exclude_unset=True)
    assert result.data.provenance["pathlens_import"]["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result.data.provenance["bloodhound"] == {"literals": []}
    analysis = analyze_graph(graph, "bhce:101", "bhce:205")
    assert analysis.exploitability == "not_assessed"
    assert len(analysis.relationships[0]) == 3
    unknown = next(r for r in analysis.relationships[0] if not r.recognized)
    assert unknown.semantics_status == "unknown"
    assert unknown.exploitability == "not_assessed"
    assert any("Unknown node type" in d for d in result.diagnostics)


def test_identity_never_uses_names_or_object_ids():
    document = minimal()
    for node in document["nodes"].values():
        node.update(label="SAME", objectId="SAME")
    result = parse_ce_graph(encoded(document))
    assert [n.id for n in result.data.nodes] == ["bhce:a", "bhce:b"]
    assert result.data.edges[0].target == "bhce:b"


def test_identical_bytes_identical_results_and_round_trip():
    first = read_ce_graph(FIXTURE)
    second = read_ce_graph(FIXTURE)
    assert first == second
    content = serialize_graph(first.data)
    assert content == serialize_graph(second.data)
    assert GraphData.model_validate(json.loads(content)) == first.data


def test_reordered_tied_paths():
    document = {
        "nodes": {key: {"kind": "Group"} for key in ["s", "b", "a", "t"]},
        "edges": [
            {"id": str(i), "source": source, "target": target, "kind": "MemberOf"}
            for i, (source, target) in enumerate([("s", "b"), ("b", "t"), ("s", "a"), ("a", "t")])
        ],
    }
    first = parse_ce_graph(encoded(document))
    document["nodes"] = dict(reversed(list(document["nodes"].items())))
    document["edges"].reverse()
    second = parse_ce_graph(encoded(document))
    for result in (first, second):
        assert shortest_node_path(build_graph(result.data), "bhce:s", "bhce:t") == ["bhce:s", "bhce:a", "bhce:t"]
    assert [(e.source, e.target, e.relation) for e in first.data.edges] == [
        (e.source, e.target, e.relation) for e in second.data.edges
    ]


@pytest.mark.parametrize("raw", [
    b"", b"{", b"[]", b"\xff", b'{"nodes":{},"nodes":{},"edges":[]}',
    b'{"nodes":{},"edges":[],"extra":{"a":1,"a":2}}',
    b'{"nodes":{},"edges":[],"n":NaN}',
    b'{"nodes":{},"edges":[],"n":Infinity}',
    b'{"nodes":{},"edges":[],"n":-Infinity}',
    b'{"nodes":{},"edges":[],"n":1e400}',
    b'{"nodes":{},"edges":[]} trailing',
])
def test_strict_json_failures(raw):
    with pytest.raises(ImportValidationError):
        parse_ce_graph(raw)


@pytest.mark.parametrize("value", ["", " ", " a", "a ", "a\nb", "\x00", "\ud800", 1, True, None, [], {}])
@pytest.mark.parametrize("field", ["source", "target", "id", "kind"])
def test_invalid_edge_identifiers(value, field):
    document = minimal()
    document["edges"][0][field] = value
    with pytest.raises(ImportValidationError, match=f"/edges/0/{field}"):
        parse_ce_graph(encoded(document))


@pytest.mark.parametrize("key", ["", " ", " a", "a\n", "\udfff"])
def test_invalid_node_keys(key):
    with pytest.raises(ImportValidationError):
        parse_ce_graph(encoded({"nodes": {key: {"kind": "User"}}, "edges": []}))


@pytest.mark.parametrize("document,message", [
    ({"data": [], "meta": {"version": 5, "type": "users"}}, "collector"),
    ({"nodes": [], "edges": [], "spotlight": {}}, "node-array"),
    ({"data": {"nodes": {}, "edges": []}}, "wrapped"),
    ({"graph": {"nodes": [], "edges": []}}, "/nodes"),
    ({"nodes": {}, "edges": {}}, "/edges"),
])
def test_unsupported_shapes(document, message):
    with pytest.raises(ImportValidationError, match=message):
        parse_ce_graph(encoded(document))


def test_dangling_references_and_conflicting_edge_ids():
    document = minimal()
    document["edges"][0]["source"] = "missing"
    with pytest.raises(ImportValidationError, match="dangling"):
        parse_ce_graph(encoded(document))
    document = minimal()
    document["edges"].append({**document["edges"][0], "kind": "WriteDacl"})
    with pytest.raises(ImportValidationError, match="duplicate"):
        parse_ce_graph(encoded(document))


@pytest.mark.parametrize("record,field,value", [
    ("node", "kind", None), ("node", "kinds", "User"),
    ("node", "kinds", [1]), ("node", "objectId", 1),
    ("node", "hidden", "false"), ("node", "isTierZero", 0),
    ("edge", "properties", []), ("edge", "label", None),
    ("edge", "lastSeen", 1),
])
def test_malformed_fields(record, field, value):
    document = minimal()
    target = document["nodes"]["a"] if record == "node" else document["edges"][0]
    target[field] = value
    with pytest.raises(ImportValidationError):
        parse_ce_graph(encoded(document))


def test_metadata_extensions_and_kind_label_mismatch():
    document = minimal()
    document["provenance"] = {"original": [None, False, 0]}
    document["nodes"]["a"]["evidence"] = None
    document["edges"][0]["label"] = "GenericAll"
    document["edges"][0]["provenance"] = {"validated": True}
    result = parse_ce_graph(encoded(document))
    assert result.data.edges[0].relation == "MemberOf"
    assert result.data.provenance["bloodhound"]["provenance"] == document["provenance"]
    assert result.data.nodes[0].provenance["bloodhound"]["record"]["evidence"] is None
    assert any("label differs" in d for d in result.diagnostics)
    assert any("Additional" in d for d in result.diagnostics)


def test_all_limits_and_boundaries(tmp_path):
    raw = encoded(minimal())
    limits = replace(DEFAULT_LIMITS, max_bytes=len(raw), max_nodes=2, max_edges=1, max_depth=3)
    assert parse_ce_graph(raw, limits)
    for field, value in [("max_bytes", len(raw)-1), ("max_nodes", 1), ("max_edges", 0), ("max_depth", 2)]:
        with pytest.raises(ImportValidationError):
            parse_ce_graph(raw, replace(limits, **{field: value}))
    path = tmp_path / "large.json"
    path.write_bytes(raw)
    with pytest.raises(ImportValidationError, match="bytes"):
        read_ce_graph(path, replace(limits, max_bytes=10))
    with pytest.raises(ImportValidationError, match="nesting"):
        parse_ce_graph(b"[" * 1000 + b"]" * 1000)


def test_brackets_and_escapes_inside_strings_do_not_count_as_depth():
    document = minimal()
    document["nodes"]["a"]["label"] = 'escaped \\" ' + "[" * 100
    assert parse_ce_graph(encoded(document), replace(DEFAULT_LIMITS, max_depth=3))


def invoke_import(path, *args):
    return runner.invoke(app, ["import", "bloodhound", "--input", str(path), "--format", "ce-graph", *args])


def test_stdout_and_end_to_end(tmp_path):
    result = invoke_import(FIXTURE)
    assert result.exit_code == 0, result.output
    data = GraphData.model_validate(json.loads(result.stdout))
    assert len(data.edges) == 4
    assert "Imported 3 nodes and 4 relationships." in result.stderr
    output = tmp_path / "normalized.json"
    imported = invoke_import(FIXTURE, "--output", str(output))
    assert imported.exit_code == 0, imported.output
    assert imported.stdout == ""
    assert output.read_text() == result.stdout
    analyzed = runner.invoke(app, [
        "analyze", "--input", str(output), "--source", "bhce:101", "--target", "bhce:205",
    ])
    assert analyzed.exit_code == 0, analyzed.output
    assert "3 relationships" in analyzed.output
    assert analyzed.output.count("[1] bhce:101 -> bhce:205 (MemberOf)") == 2
    assert "Semantics: unknown." in analyzed.output
    assert "Exploitability: not assessed." in analyzed.output


def test_invalid_input_never_emits_output(tmp_path):
    source = tmp_path / "bad.json"
    source.write_text('{"nodes":')
    output = tmp_path / "output.json"
    for args in [(), ("--output", str(output))]:
        result = invoke_import(source, *args)
        assert result.exit_code == 2
        assert result.stdout == ""
        assert not output.exists()
    assert not list(tmp_path.glob(".pathlens-*"))


def test_existing_output_input_collision_and_symlink(tmp_path):
    source = tmp_path / "input.json"
    source.write_bytes(FIXTURE.read_bytes())
    existing = tmp_path / "existing.json"
    existing.write_text("KEEP")
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(existing)
    dangling = tmp_path / "dangling.json"
    dangling.symlink_to(tmp_path / "absent.json")
    for target in [existing, source, symlink, dangling]:
        result = invoke_import(source, "--output", str(target))
        assert result.exit_code == 1
        assert result.stdout == ""
    assert existing.read_text() == "KEEP"
    assert source.read_bytes() == FIXTURE.read_bytes()
    assert symlink.is_symlink() and dangling.is_symlink()
    assert not (tmp_path / "absent.json").exists()
    assert not list(tmp_path.glob(".pathlens-*"))


def test_atomic_publication_and_race(tmp_path, monkeypatch):
    import os
    real_link = os.link
    output = tmp_path / "output.json"

    def racing_link(source, target):
        assert Path(source).read_text() == "COMPLETE"
        assert not Path(target).exists()
        Path(target).write_text("OTHER WRITER")
        real_link(source, target)

    monkeypatch.setattr("pathlens.importers.bloodhound.os.link", racing_link)
    with pytest.raises(FileExistsError):
        write_new_file(output, "COMPLETE")
    assert output.read_text() == "OTHER WRITER"
    assert not list(tmp_path.glob(".pathlens-*"))


def test_write_failure_cleans_temporary_file(tmp_path, monkeypatch):
    def fail(_fd):
        raise OSError("synthetic fsync failure")
    monkeypatch.setattr("pathlens.importers.bloodhound.os.fsync", fail)
    output = tmp_path / "output"
    with pytest.raises(OSError):
        write_new_file(output, "COMPLETE")
    assert not output.exists()
    assert not list(tmp_path.glob(".pathlens-*"))


def test_cli_io_errors_and_unsupported_format(tmp_path):
    assert invoke_import(tmp_path / "missing").exit_code == 1
    assert invoke_import(FIXTURE, "--output", str(tmp_path / "absent" / "out")).exit_code == 1
    result = runner.invoke(app, ["import", "bloodhound", "--input", str(FIXTURE), "--format", "legacy"])
    assert result.exit_code == 2
    assert result.stdout == ""


def test_empty_graph_and_escaped_pointer():
    assert parse_ce_graph(b'{"nodes":{},"edges":[]}').data.nodes == []
    data = parse_ce_graph(encoded({"nodes": {"a/b~c": {"kind": "User"}}, "edges": []})).data
    assert data.nodes[0].id == "bhce:a/b~c"
    assert data.nodes[0].provenance["bloodhound"]["source_location"] == "/nodes/a~1b~0c"


EXPLORE_FIXTURE = FIXTURE.with_name("ce_explore_graph.json")


def explore_minimal():
    document = minimal()
    document["edges"][0]["exploreGraphId"] = document["edges"][0].pop("id")
    return document


def test_explore_fixture_identity_metadata_and_round_trip():
    from pathlens.native import parse_native_graph
    from pathlens.reporting import build_report, render_json

    raw = EXPLORE_FIXTURE.read_bytes()
    original = json.loads(raw)
    result = parse_ce_graph(raw)
    assert result == parse_ce_graph(raw)
    assert (len(result.data.nodes), len(result.data.edges)) == (9, 23)
    assert parse_native_graph(serialize_graph(result.data).encode()) == result.data
    graph = build_graph(result.data)
    assert graph.number_of_nodes() == 9 and graph.number_of_edges() == 23
    assert graph.number_of_edges("bhce:1", "bhce:2") == 3
    with pytest.raises(nx.NetworkXNoPath):
        shortest_node_path(graph, "bhce:2", "bhce:1")
    for node in result.data.nodes:
        assert node.provenance["bloodhound"]["record"] == original["nodes"][node.id[5:]]
    ids = set()
    for edge in result.data.edges:
        provenance = edge.provenance["bloodhound"]
        record = original["edges"][int(provenance["source_location"].split("/")[-1])]
        assert provenance["record"] == record
        assert provenance["edge_id"] == record["exploreGraphId"]
        assert provenance["edge_id_field"] == "exploreGraphId"
        assert provenance["identity_scope"] == "export_local"
        assert (edge.source, edge.target, edge.relation) == (
            "bhce:" + record["source"], "bhce:" + record["target"], record["kind"])
        assert "evidence" not in edge.model_dump(exclude_unset=True)
        ids.add(provenance["edge_id"])
    assert len(ids) == 23 and "rel_1183" in ids
    report = json.loads(render_json(build_report(analyze_graph(graph, "bhce:1", "bhce:2"))))
    assert report["relationship_count"] == 3
    assert report["exploitability"] == "not_assessed"
    assert report["independently_validated_findings"] == []
    assert {r["assertion"]["provenance"]["bloodhound"]["edge_id"]
            for r in report["hops"][0]["relationships"]} == {"rel_1183", "rel_1184", "rel_1185"}


@pytest.mark.parametrize("value", ["", " ", " a", "a ", "a\nb", "\x00", "\x7f", "\ud800", 1, True, None, [], {}])
def test_invalid_explore_ids(value):
    document = explore_minimal()
    document["edges"][0]["exploreGraphId"] = value
    with pytest.raises(ImportValidationError, match="/edges/0/exploreGraphId"):
        parse_ce_graph(encoded(document))


@pytest.mark.parametrize("field", ["source", "target", "exploreGraphId"])
def test_missing_explore_fields(field):
    document = explore_minimal()
    del document["edges"][0][field]
    with pytest.raises(ImportValidationError):
        parse_ce_graph(encoded(document))


@pytest.mark.parametrize("field", ["source", "target"])
def test_explore_dangling_endpoints(field):
    document = explore_minimal()
    document["edges"][0][field] = "absent"
    with pytest.raises(ImportValidationError, match=f"/edges/0/{field}: dangling"):
        parse_ce_graph(encoded(document))


@pytest.mark.parametrize("factory", [minimal, explore_minimal])
@pytest.mark.parametrize("change", [{}, {"kind": "WriteDacl"}, {"source": "b", "target": "a"}])
def test_all_duplicate_ids_rejected(factory, change):
    document = factory()
    document["edges"].append({**document["edges"][0], **change})
    with pytest.raises(ImportValidationError, match="duplicate edge ID"):
        parse_ce_graph(encoded(document))


def test_id_aliases_are_validated_without_fallback_or_cross_namespace_collision():
    document = explore_minimal()
    edge = document["edges"][0]
    edge["id"] = "e"
    assert parse_ce_graph(encoded(document)).data.edges[0].provenance["bloodhound"]["edge_id"] == "e"
    for value in [None, "", 1, "different"]:
        edge["id"] = value
        with pytest.raises(ImportValidationError):
            parse_ce_graph(encoded(document))
    edge.pop("id")
    document["edges"].append(minimal()["edges"][0])
    with pytest.raises(ImportValidationError, match="duplicate edge ID"):
        parse_ce_graph(encoded(document))


@pytest.mark.parametrize("value", [None, [], {}, "opaque", {"id": None, "exploreGraphId": "unrelated"}])
def test_explore_data_is_opaque(value):
    document = explore_minimal()
    document["edges"][0]["data"] = value
    result = parse_ce_graph(encoded(document))
    assert result.data.edges[0].provenance["bloodhound"]["record"]["data"] == value


def test_explore_duplicate_keys_rejected():
    for raw in [
        b'{"nodes":{"a":{"kind":"User"},"a":{"kind":"User"}},"edges":[]}',
        b'{"nodes":{},"edges":[{"exploreGraphId":"a","exploreGraphId":"b"}]}',
        b'{"nodes":{},"edges":[{"data":{"x":1,"x":2}}]}',
    ]:
        with pytest.raises(ImportValidationError, match="Duplicate JSON object key"):
            parse_ce_graph(raw)


def test_explore_duplicate_failure_does_not_publish(tmp_path):
    document = explore_minimal()
    document["edges"] *= 2
    source, output = tmp_path / "input.json", tmp_path / "output.json"
    source.write_bytes(encoded(document))
    for args in [(), ("--output", str(output))]:
        result = invoke_import(source, *args)
        assert result.exit_code == 2 and result.stdout == ""
        assert not output.exists()
    assert not list(tmp_path.glob(".pathlens-*"))


@pytest.mark.parametrize("format", ["terminal", "json", "markdown"])
def test_explore_import_analyze_report(tmp_path, format):
    output = tmp_path / "normalized.json"
    result = invoke_import(EXPLORE_FIXTURE, "--output", str(output))
    assert result.exit_code == 0, result.output
    assert "Imported 9 nodes and 23 relationships." in result.stderr
    result = runner.invoke(app, ["analyze", "--input", str(output), "--source", "bhce:1",
                                 "--target", "bhce:2", "--format", format])
    assert result.exit_code == 0, result.output
    if format == "json":
        assert json.loads(result.stdout)["relationship_count"] == 3
    elif format == "markdown":
        assert "rel_1183" in result.stdout
    else:
        assert "3 relationships" in result.stdout
