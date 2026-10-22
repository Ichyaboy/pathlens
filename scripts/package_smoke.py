"""Run with the artifact environment's Python -I, from outside the checkout."""

import argparse
from importlib.metadata import distribution
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True, help="Repository or extracted sdist root")
    args = parser.parse_args()
    fixtures = args.fixtures.resolve()
    import pathlens

    assert Path(pathlens.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    dist = distribution("pathlens")
    assert dist.version == pathlens.__version__ == "0.1.0"
    direct = json.loads(dist.read_text("direct_url.json") or "{}")
    assert not direct.get("dir_info", {}).get("editable", False)
    cli = Path(sys.executable).parent / ("pathlens.exe" if sys.platform == "win32" else "pathlens")

    with tempfile.TemporaryDirectory(prefix="pathlens-smoke-") as temporary:
        work = Path(temporary)

        def run(*arguments: str, code: int = 0) -> subprocess.CompletedProcess[str]:
            result = subprocess.run([str(cli), *arguments], cwd=work, capture_output=True,
                                    text=True, check=False, timeout=30)
            assert result.returncode == code, (arguments, result.stdout, result.stderr)
            assert "Traceback" not in result.stdout + result.stderr
            return result

        for command in [(), ("analyze",), ("import", "bloodhound")]:
            assert "Usage" in run(*command, "--help").stdout
        native = ("analyze", "--input", str(fixtures / "data/sample_domain.json"),
                  "--source", "ICHYABOY", "--target", "DOMAIN ADMINS")
        assert "3 relationships" in run(*native).stdout
        normalized = work / "normalized.json"
        run("import", "bloodhound", "--input", str(fixtures / "tests/fixtures/bloodhound/ce_graph.json"),
            "--output", str(normalized))
        imported = ("analyze", "--input", str(normalized), "--source", "bhce:101", "--target", "bhce:205")
        explore_normalized = work / "explore-normalized.json"
        result = run("import", "bloodhound", "--input",
                     str(fixtures / "tests/fixtures/bloodhound/ce_explore_graph.json"),
                     "--output", str(explore_normalized))
        assert "Imported 9 nodes and 23 relationships." in result.stderr
        explore_data = json.loads(explore_normalized.read_text())
        assert len(explore_data["nodes"]) == 9 and len(explore_data["edges"]) == 23
        explore = ("analyze", "--input", str(explore_normalized),
                   "--source", "bhce:1", "--target", "bhce:2")
        assert "3 relationships" in run(*explore).stdout
        for number, command in enumerate([native, imported, explore]):
            report = json.loads(run(*command, "--format", "json").stdout)
            assert report["relationship_count"] == 3
            assert report["exploitability"] == "not_assessed"
            assert report["independently_validated_findings"] == []
            output = work / f"report-{number}.md"
            run(*command, "--format", "markdown", "--output", str(output))
            assert output.read_text().startswith("# PathLens security report")
            run(*command, "--format", "markdown", "--output", str(output), code=1)
        invalid = work / "invalid.json"
        invalid.write_text('{"nodes":[],"edges":[],"evidence":' + '[' * 11000 + '0' + ']' * 11000 + '}')
        result = run("analyze", "--input", str(invalid), "--source", "A", "--target", "B",
                     "--format", "json", code=2)
        assert result.stdout == "" and "nesting" in result.stderr
    print(f"Packaged CLI smoke tests passed: Python {sys.version.split()[0]}, {pathlens.__file__}")


if __name__ == "__main__":
    main()
