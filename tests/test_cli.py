import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pathlens.cli import EXPLANATIONS, app


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


def test_graph_output_is_literal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = "[bold]ALICE[/bold]"
    target = "[red]ADMINS[/red]"
    relation = "[italic]MemberOf[/italic]"
    description = "[green]Evidence[/green]"
    monkeypatch.setitem(EXPLANATIONS, relation, description)
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
    assert description in output


def test_validation_error_is_literal(tmp_path: Path):
    input_path = tmp_path / "invalid.json"
    input_path.write_text(json.dumps({
        "nodes": [{"id": "A", "type": "User"}],
        "edges": [{"source": "A", "target": "[bold]MISSING[/bold]", "relation": "MemberOf"}],
    }), encoding="utf-8")

    result = analyze(input_path, "A", "B")

    assert result.exit_code == 2
    assert "[bold]MISSING[/bold]" in result.output
