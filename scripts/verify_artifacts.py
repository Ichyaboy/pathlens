"""Install and test wheel and sdist separately, using locked dependencies and uv."""

import argparse
from email.parser import BytesParser
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, cwd: Path = ROOT) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def check_contents(wheel: Path, sdist: Path) -> None:
    """Catch incomplete sdists, accidental wheel contents and metadata regressions."""
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert all(name.startswith(("pathlens/", "pathlens-0.1.0.dist-info/")) for name in names)
        metadata = BytesParser().parsebytes(archive.read("pathlens-0.1.0.dist-info/METADATA"))
        assert metadata["Name"] == "pathlens" and metadata["Version"] == "0.1.0"
        assert metadata["Requires-Python"] == "<3.13,>=3.11"
        assert metadata["Description-Content-Type"] == "text/markdown"
        assert "# PathLens" in metadata.get_payload()
        assert "pathlens = pathlens.cli:app" in archive.read(
            "pathlens-0.1.0.dist-info/entry_points.txt").decode()
        for source in (ROOT / "src/pathlens").rglob("*.py"):
            assert source.relative_to(ROOT / "src").as_posix() in names
    with tarfile.open(sdist) as archive:
        names = set(archive.getnames())
        for relative in ["README.md", "pyproject.toml", "uv.lock", "data/sample_domain.json",
                         "tests/fixtures/bloodhound/ce_graph.json", "scripts/package_smoke.py",
                         "scripts/verify_artifacts.py"]:
            assert f"pathlens-0.1.0/{relative}" in names
        for test in (ROOT / "tests").glob("test_*.py"):
            assert f"pathlens-0.1.0/tests/{test.name}" in names
    print("Artifact contents and metadata verified", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    artifacts = [args.dist / "pathlens-0.1.0-py3-none-any.whl",
                 args.dist / "pathlens-0.1.0.tar.gz"]
    for artifact in artifacts:
        if not artifact.is_file():
            parser.error(f"Missing artifact: {artifact}")
    check_contents(*artifacts)
    with tempfile.TemporaryDirectory(prefix="pathlens-artifacts-") as temporary:
        work = Path(temporary)
        requirements = work / "requirements.txt"
        subprocess.run(["uv", "export", "--locked", "--extra", "dev", "--no-emit-project",
                        "--output-file", str(requirements)], cwd=ROOT, check=True,
                       stdout=subprocess.DEVNULL)
        for index, artifact in enumerate(artifacts):
            environment = work / f"env-{index}"
            run("uv", "venv", "--python", args.python, str(environment))
            python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
            run("uv", "pip", "install", "--python", str(python), "--require-hashes", "-r", str(requirements))
            run("uv", "pip", "install", "--python", str(python), "--no-deps", str(artifact.resolve()))
            run("uv", "pip", "check", "--python", str(python))
            run(str(python), "-I", str(ROOT / "scripts/package_smoke.py"), "--fixtures", str(ROOT), cwd=work)
            run(str(python), "-I", "-m", "pytest", "--import-mode=importlib", "-q", str(ROOT / "tests"), cwd=work)
            print(f"Verified {artifact.name}", flush=True)


if __name__ == "__main__":
    main()
