import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pathlens.cli import app


SAMPLE = Path(__file__).resolve().parents[1] / "data" / "sample_domain.json"
runner = CliRunner()


def analyze(input_path: Path, source: str, target: str):
    return runner.invoke(app, [
        "analyze", "--input", str(input_path), "--source", source, "--target", target,
    ])


def test_sample_analysis():
    result = analyze(SAMPLE, "ICHYABOY", "DOMAIN ADMINS")

    assert result.exit_code == 0, result.output
    assert "3 relationships" in result.output
    assert "[1] ICHYABOY -> HELPDESK (MemberOf)" in result.output
    assert "[2] HELPDESK -> IT-ADMINS (GenericAll)" in result.output
    assert "[3] IT-ADMINS -> DOMAIN ADMINS (MemberOf)" in result.output
    assert "A graph path is not proof of exploitability." in result.output


@pytest.mark.parametrize(("source", "target"), [
    ("MISSING", "DOMAIN ADMINS"),
    ("ICHYABOY", "MISSING"),
])
def test_unknown_endpoint(source: str, target: str):
    result = analyze(SAMPLE, source, target)

    assert result.exit_code == 2
    assert "Unknown source or target." in result.output


def test_malformed_json(tmp_path: Path):
    input_path = tmp_path / "malformed.json"
    input_path.write_text('{"nodes":', encoding="utf-8")

    result = analyze(input_path, "A", "B")

    assert result.exit_code == 2
    assert "Invalid input:" in result.output


def test_no_directed_path():
    result = analyze(SAMPLE, "DOMAIN ADMINS", "ICHYABOY")

    assert result.exit_code == 1
    assert "No directed path found." in result.output


def test_help_lists_analyze():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Commands" in result.output
    assert "analyze" in result.output


def test_graph_output_is_literal(tmp_path: Path):
    source = "[bold]ALICE[/bold]"
    target = "[red]ADMINS[/red]"
    relation = "[italic]MemberOf[/italic]"
    input_path = tmp_path / "markup.json"
    input_path.write_text(json.dumps({
        "nodes": [{"id": source, "type": "User"}, {"id": target, "type": "Group"}],
        "edges": [{"source": source, "target": target, "relation": relation}],
    }), encoding="utf-8")

    result = analyze(input_path, source, target)

    assert result.exit_code == 0, result.output
    # Ignore terminal wrapping while requiring every literal markup tag.
    output = " ".join(result.output.split())
    assert f"{source} -> {target} ({relation})" in output
    assert "Unrecognized relationship; no security conclusion available." in output


def test_validation_error_is_literal(tmp_path: Path):
    input_path = tmp_path / "invalid.json"
    input_path.write_text(json.dumps({
        "nodes": [{"id": "A", "type": "User"}],
        "edges": [{"source": "A", "target": "[bold]MISSING[/bold]", "relation": "MemberOf"}],
    }), encoding="utf-8")

    result = analyze(input_path, "A", "B")

    assert result.exit_code == 2
    assert "[bold]MISSING[/bold]" in result.output


def test_parallel_and_reordered_cli_output(tmp_path: Path):
    data = {
        "nodes": [{"id": node, "type": "Group"} for node in ["S", "B", "A", "T"]],
        "edges": [
            {"source": start, "target": end, "relation": relation}
            for start, end, relation in [
                ("S", "B", "MemberOf"), ("B", "T", "MemberOf"),
                ("S", "A", "UnknownPermission"), ("S", "A", "MemberOf"),
                ("A", "T", "GenericWrite"),
            ]
        ],
    }
    input_path = tmp_path / "parallel.json"
    input_path.write_text(json.dumps(data), encoding="utf-8")
    result = analyze(input_path, "S", "T")
    assert result.exit_code == 0, result.output
    assert "3 relationships" in result.output
    assert "[1] S -> A (MemberOf)" in result.output
    assert "[1] S -> A (UnknownPermission)" in result.output
    assert "[2] A -> T (GenericWrite)" in result.output
    assert "Unrecognized relationship; no security conclusion available." in result.output
    data["nodes"].reverse()
    data["edges"].reverse()
    input_path.write_text(json.dumps(data), encoding="utf-8")
    reordered = analyze(input_path, "S", "T")
    assert reordered.exit_code == 0
    assert reordered.output == result.output


def test_isolated_node_cli(tmp_path: Path):
    input_path = tmp_path / "isolated.json"
    input_path.write_text(json.dumps({
        "nodes": [{"id": node, "type": "User"} for node in ["A", "B"]],
        "edges": [],
    }), encoding="utf-8")
    disconnected = analyze(input_path, "A", "B")
    assert disconnected.exit_code == 1
    assert "No directed path found." in disconnected.output
    same = analyze(input_path, "A", "A")
    assert same.exit_code == 0
    assert "0 relationships" in same.output


def test_cli_semantics_and_endpoint_warning_are_literal(tmp_path: Path):
    input_path = tmp_path / "semantics.json"
    input_path.write_text(json.dumps({
        "nodes": [{"id": "A", "type": "User"},
                  {"id": "B", "type": "[bold]User[/bold]"}],
        "edges": [{"source": "A", "target": "B", "relation": "AddMember",
                   "provenance": "PRIVATE_FIXTURE_MARKER"}],
    }))
    result = analyze(input_path, "A", "B")
    assert result.exit_code == 0
    output = " ".join(result.output.split())
    assert "Warning: AddMember expects target type Group" in output
    assert "[bold]User[/bold]" in output
    assert "Requires validation:" in output
    assert "Limitation:" in output
    assert "Remediation:" in output
    assert "PRIVATE_FIXTURE_MARKER" not in output
    assert "A graph path is not proof of exploitability." in output


@pytest.mark.parametrize("relation", [
    "MemberOf", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AddMember",
])
def test_all_supported_cli_descriptions_separate_implication_from_fact(tmp_path: Path, relation: str):
    input_path = tmp_path / "relationship.json"
    input_path.write_text(json.dumps({
        "nodes": [{"id": "A", "type": "User"}, {"id": "B", "type": "Group"}],
        "edges": [{"source": "A", "target": "B", "relation": relation}],
    }), encoding="utf-8")
    result = analyze(input_path, "A", "B")
    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    assert f"[1] A -> B ({relation})" in output
    assert "Input asserts" in output
    assert "Potential implication:" in output
    assert "Exploitability: not assessed." in output


def test_unknown_cli_semantics_are_explicit(tmp_path: Path):
    input_path = tmp_path / "unknown.json"
    input_path.write_text(json.dumps({
        "nodes": [{"id": "A", "type": "User"}, {"id": "B", "type": "Group"}],
        "edges": [{"source": "A", "target": "B", "relation": "FutureRelationship"}],
    }), encoding="utf-8")
    result = analyze(input_path, "A", "B")
    assert result.exit_code == 0
    assert "Semantics: unknown." in result.output
    assert "Potential implication:" not in result.output
    assert "Exploitability: not assessed." in result.output
