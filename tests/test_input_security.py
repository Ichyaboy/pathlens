"""Synthetic regressions for the v0.1.0 release audit."""

from dataclasses import replace
from io import BytesIO
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pathlens.cli import app
from pathlens.graph import GraphData
from pathlens.importers.bloodhound import (
    DEFAULT_LIMITS, parse_ce_graph, read_ce_graph, serialize_graph,
)
from pathlens.json_input import InputLimits, InputValidationError, NATIVE_LIMITS, parse_json
from pathlens.native import parse_native_graph, read_native_graph
from pathlens.terminal import terminal_text

SECRET = "SYNTHETIC_SECRET_MARKER"
runner = CliRunner()


def native():
    return {"nodes": [{"id": "A", "type": "User"}, {"id": "B", "type": "Group"}],
            "edges": [{"source": "A", "target": "B", "relation": "MemberOf"}]}


def ce():
    return {"nodes": {"A": {"kind": "User"}, "B": {"kind": "Group"}},
            "edges": [{"id": "1", "source": "A", "target": "B", "kind": "MemberOf"}]}


def invoke(path, command, *extra):
    args = (["analyze", "--source", "A", "--target", "B"] if command == "analyze"
            else ["import", "bloodhound"])
    return runner.invoke(app, [*args, "--input", str(path), *extra])


@pytest.mark.parametrize("command", ["analyze", "import"])
@pytest.mark.parametrize("bad", [
    b"\xff", b"{", b"[]", b"null", b"{} trailing",
    b'{"nodes":[],"nodes":[],"edges":[]}',
    b'{"nodes":[],"edges":[],"evidence":{"claim":1,"claim":2}}',
    b'{"nodes":[],"edges":[],"evidence":{"nested":[{"x":0,"x":1}]}}',
    *[b'{"nodes":[],"edges":[],"evidence":' + number + b'}'
      for number in [b'NaN', b'Infinity', b'-Infinity', b'1e400', b'-1e400']],
    b'{"nodes":[],"edges":[],"evidence":' + b'[' * 11000 + b'0' + b']' * 11000 + b'}',
])
def test_bad_json_has_safe_exit_and_no_publication(tmp_path, command, bad):
    path = tmp_path / "input.json"
    path.write_bytes(bad)
    output = tmp_path / "output.json"
    extra = ["--output", str(output)]
    if command == "analyze":
        extra += ["--format", "json"]
    result = invoke(path, command, *extra)
    assert result.exit_code == 2, result.output
    assert result.stdout == ""
    assert result.stderr
    assert "Traceback" not in result.output
    assert not output.exists()


def test_native_limit_boundaries():
    raw = json.dumps(native()).encode()
    limits = InputLimits(max_bytes=len(raw), max_depth=3, max_nodes=2, max_edges=1)
    assert parse_native_graph(raw, limits)
    for field, value in [("max_bytes", len(raw)-1), ("max_depth", 2),
                         ("max_nodes", 1), ("max_edges", 0)]:
        with pytest.raises(InputValidationError):
            parse_native_graph(raw, replace(limits, **{field: value}))


@pytest.mark.parametrize("reader", [read_native_graph, read_ce_graph])
def test_file_reads_are_bounded(monkeypatch, reader):
    class LimitedStream(BytesIO):
        def read(self, size=-1):
            assert size == 11
            return super().read(size)
    monkeypatch.setattr(Path, "open", lambda *a, **kw: LimitedStream(b" " * 100))
    with pytest.raises(InputValidationError, match="bytes"):
        reader(Path("unused"), InputLimits(max_bytes=10))


def test_depth_scanner_handles_quotes_and_escapes():
    raw = native()
    raw["evidence"] = '\\"[' * 100
    assert parse_native_graph(json.dumps(raw).encode(), replace(NATIVE_LIMITS, max_depth=3))


def test_decoder_recursion_failure_is_safe(monkeypatch):
    def fail(*args, **kwargs):
        raise RecursionError(SECRET)
    monkeypatch.setattr("pathlens.json_input.json.loads", fail)
    with pytest.raises(InputValidationError) as exc:
        parse_json(b"{}", NATIVE_LIMITS)
    assert SECRET not in str(exc.value)


@pytest.mark.parametrize("field", ["id", "type"])
@pytest.mark.parametrize("value", [1, True, None, [], {}])
def test_native_strings_are_not_coerced(field, value):
    raw = native()
    raw["nodes"][0][field] = value
    with pytest.raises(InputValidationError):
        parse_native_graph(json.dumps(raw).encode())


@pytest.mark.parametrize("field", ["source", "target", "relation"])
@pytest.mark.parametrize("value", [1, True, None, [], {}])
def test_native_edge_types_are_strict(field, value):
    raw = native()
    raw["edges"][0][field] = value
    with pytest.raises(InputValidationError):
        parse_native_graph(json.dumps(raw).encode())


@pytest.mark.parametrize("format", ["terminal", "json", "markdown"])
@pytest.mark.parametrize("failure", ["dangling", "extra", "field", "duplicate", "metadata_key"])
def test_errors_never_disclose_input_values(tmp_path, format, failure):
    raw = native()
    raw["evidence"] = {"secret": SECRET}
    raw["provenance"] = {"secret": SECRET}
    raw["edges"][0]["evidence"] = {"secret": SECRET}
    raw["edges"][0]["provenance"] = {"secret": SECRET}
    if failure == "dangling":
        raw["edges"][0]["target"] = SECRET
    elif failure == "extra":
        raw[SECRET] = {"secret": SECRET}
    elif failure == "field":
        raw["nodes"][0]["type"] = {"secret": SECRET}
    elif failure == "duplicate":
        raw["nodes"].append(raw["nodes"][0])
    else:
        raw["evidence"] = {SECRET: float("inf")}
    path = tmp_path / "input.json"
    path.write_text(json.dumps(raw))
    result = invoke(path, "analyze", "--format", format)
    assert result.exit_code == 2
    assert SECRET not in result.output
    assert "input_value" not in result.output
    assert "Traceback" not in result.output
    if format != "terminal":
        assert result.stdout == ""


CONTROLS = [chr(i) for i in range(32)] + ["\x7f", "\x85", "\x9b", "\u061c", "\u200e", "\u200f",
    *[chr(i) for i in range(0x202a, 0x202f)],
    *[chr(i) for i in range(0x2066, 0x206a)], "\u2028", "\u2029", "\ud800"]


@pytest.mark.parametrize("control", CONTROLS)
def test_display_escaping(control):
    assert control not in terminal_text("A" + control + "B")
    assert terminal_text("A" + control + "B") == "A" + json.dumps(control)[1:-1] + "B"


def test_terminal_controls_and_structured_values(tmp_path):
    attack = "A\nFORGED\x1b[2J\u202e"
    raw = native()
    raw["nodes"][0]["id"] = attack
    raw["nodes"][1]["type"] = "Unknown\x1b[2J\u202e"
    raw["edges"][0]["source"] = attack
    raw["edges"].append({"source": attack, "target": "B", "relation": attack})
    path = tmp_path / "input.json"
    path.write_text(json.dumps(raw))
    args = ["analyze", "--input", str(path), "--source", attack, "--target", "B"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output and "\u202e" not in result.output
    assert "\nFORGED" not in result.output
    assert "\\nFORGED\\u001b[2J\\u202e" in result.output
    structured = runner.invoke(app, args + ["--format", "json"])
    assert structured.exit_code == 0
    report = json.loads(structured.stdout)
    assert report["source"] == attack
    assert any(r["assertion"]["relation"] == attack for r in report["hops"][0]["relationships"])
    markdown = runner.invoke(app, args + ["--format", "markdown"])
    assert markdown.exit_code == 0
    assert "\x1b" not in markdown.stdout and "\u202e" not in markdown.stdout


def test_import_errors_and_diagnostics_are_terminal_safe(tmp_path):
    path = tmp_path / "input.json"
    raw = ce()
    raw["nodes"]["B"]["kind"] = "Unknown\u202e"
    path.write_text(json.dumps(raw))
    result = invoke(path, "import")
    assert result.exit_code == 0
    assert "\u202e" not in result.stderr
    assert json.loads(result.stdout)["nodes"][1]["type"] == "Unknown\u202e"
    raw["nodes"]["bad\n\x1b[2J\u202e"] = {"kind": "User", "evidence": SECRET}
    path.write_text(json.dumps(raw))
    result = invoke(path, "import")
    assert result.exit_code == 2
    assert "\x1b" not in result.output and "\u202e" not in result.output
    assert SECRET not in result.output


@pytest.mark.parametrize("command", ["analyze", "import"])
def test_missing_input_filename_cannot_inject_errors(tmp_path, command):
    result = invoke(tmp_path / "missing\n\x1b[2J\u202e", command)
    assert result.exit_code == (2 if command == "analyze" else 1)
    assert "\x1b" not in result.output and "\u202e" not in result.output


def test_edge_node_named_extensions_are_opaque():
    raw = ce()
    extensions = {"objectId": None, "kinds": {"arbitrary": SECRET},
                  "isTierZero": "unknown", "isOwnedObject": [None], "hidden": 42}
    raw["edges"][0].update(extensions)
    result = parse_ce_graph(json.dumps(raw).encode())
    record = result.data.edges[0].provenance["bloodhound"]["record"]
    for key, value in extensions.items():
        assert record[key] == value
    assert any("Additional edge fields" in d for d in result.diagnostics)
    assert SECRET not in " ".join(result.diagnostics)


@pytest.mark.parametrize("field,value", [("objectId", None), ("kinds", {}),
    ("isTierZero", "unknown"), ("isOwnedObject", []), ("hidden", 42)])
def test_node_specific_fields_still_validated(field, value):
    raw = ce()
    raw["nodes"]["A"][field] = value
    with pytest.raises(InputValidationError):
        parse_ce_graph(json.dumps(raw).encode())


def test_normalized_depth_boundary_remains_readable(tmp_path):
    raw = ce()
    value = 0
    # Root -> nodes -> node -> properties -> 60 arrays = 64 containers.
    for _ in range(60):
        value = [value]
    raw["nodes"]["A"]["properties"] = {"deep": value}
    result = parse_ce_graph(json.dumps(raw).encode())
    normalized = serialize_graph(result.data)
    path = tmp_path / "normalized.json"
    path.write_text(normalized)
    assert read_native_graph(path) == result.data
    for format in ["terminal", "json", "markdown"]:
        cli = runner.invoke(app, ["analyze", "--input", str(path), "--source", "bhce:A",
                                 "--target", "bhce:B", "--format", format])
        assert cli.exit_code == 0, cli.output


def test_normalized_unicode_expansion_beyond_import_byte_limit(tmp_path):
    raw = ce()
    raw["nodes"]["A"]["label"] = "é" * (3 * 1024 * 1024)
    encoded = json.dumps(raw, ensure_ascii=False).encode()
    assert len(encoded) < DEFAULT_LIMITS.max_bytes
    imported = parse_ce_graph(encoded)
    content = serialize_graph(imported.data)
    assert DEFAULT_LIMITS.max_bytes < len(content) < NATIVE_LIMITS.max_bytes
    path = tmp_path / "normalized.json"
    path.write_text(content)
    assert read_native_graph(path) == imported.data


def test_normalized_output_limit_checked_before_publication(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlens.importers.bloodhound.NATIVE_LIMITS", replace(NATIVE_LIMITS, max_bytes=10))
    path = tmp_path / "input.json"
    path.write_text(json.dumps(ce()))
    output = tmp_path / "normalized.json"
    result = invoke(path, "import", "--output", str(output))
    assert result.exit_code == 2 and result.stdout == ""
    assert not output.exists()


def test_python_model_types_are_strict_and_errors_hide_values():
    raw = native()
    raw["nodes"][0]["id"] = SECRET.encode()
    with pytest.raises(ValueError) as exc:
        GraphData.model_validate(raw)
    assert SECRET not in str(exc.value)


def test_native_maximum_metadata_depth_in_all_formats(tmp_path):
    raw = native()
    value = 0
    for _ in range(NATIVE_LIMITS.max_depth - 1):
        value = [value]
    raw["evidence"] = value
    path = tmp_path / "input.json"
    path.write_text(json.dumps(raw))
    for format in ["terminal", "json", "markdown"]:
        result = invoke(path, "analyze", "--format", format)
        assert result.exit_code == 0, result.output
    raw["evidence"] = [value]
    path.write_text(json.dumps(raw))
    result = invoke(path, "analyze", "--format", "json")
    assert result.exit_code == 2 and result.stdout == ""


@pytest.mark.parametrize("format", ["json", "markdown"])
def test_report_io_errors_do_not_render_exception_values(tmp_path, monkeypatch, format):
    path = tmp_path / "input.json"
    path.write_text(json.dumps(native()))
    def fail(*args):
        raise OSError(SECRET + "\n\x1b[2J\u202e")
    monkeypatch.setattr("pathlens.cli.write_new_file", fail)
    result = invoke(path, "analyze", "--format", format, "--output", str(tmp_path / "report"))
    assert result.exit_code == 1 and result.stdout == ""
    assert SECRET not in result.output
    assert "\x1b" not in result.output and "\u202e" not in result.output
