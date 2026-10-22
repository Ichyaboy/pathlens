# Installation and development

[← PathLens](../README.md)

Commands below run from the repository root.

PathLens v0.1.0 supports **CPython 3.11 and 3.12**. Python 3.10 and older,
3.13 and newer, and other Python implementations are not supported by this
release. Package metadata enforces `>=3.11,<3.13`. CI runs on Ubuntu 22.04;
Windows and macOS have not been validated by this workflow.

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) first.
The CI workflow uses **uv 0.13.1**. From a checkout:

```bash
uv sync --locked --extra dev --python 3.12
uv run --no-sync pathlens --help
uv run --no-sync pathlens analyze --input data/sample_domain.json --source ICHYABOY --target "DOMAIN ADMINS"
uv run --no-sync python -m pytest -q
```

`uv sync` creates `.venv` and installs the project in editable mode for development.
The same commands work in PowerShell. For installed executable paths, use
`.venv/bin/pathlens` on Linux/macOS or `.venv\Scripts\pathlens.exe` on Windows.
The `dev` extra remains available to pip users as `python -m pip install -e ".[dev]"`;
that command resolves dependencies afresh and does not use `uv.lock`.

### Dependency reproducibility

Track `uv.lock` with `pyproject.toml`. It records exact transitive dependency
versions, Python markers, download URLs and hashes for the supported Python range.
CI uses `--locked`, which fails on stale project metadata rather than updating
resolution. Runtime dependency ranges remain in package metadata for downstream
installers; a plain wheel installation does not automatically consume our lock.
The setuptools build backend is pinned separately in `[build-system]` because
isolated build requirements are not pinned by the runtime lock.

To intentionally refresh resolution, run `uv lock --upgrade`, review the lockfile
diff, then repeat tests and artifact verification on both supported Python versions.
Use the pinned uv version for release checks. Reproducible dependency selection
does not imply byte-identical archives across operating systems or build times.

### Build and verify distributions

```bash
uv lock --check
uv build --python 3.12
uv run --no-sync python scripts/verify_artifacts.py --python 3.12
```

`uv build` produces `dist/pathlens-0.1.0.tar.gz` and
`dist/pathlens-0.1.0-py3-none-any.whl`; by default it builds the wheel from the
sdist, exercising source-distribution completeness. The sdist includes synthetic
fixtures, tests, the lockfile, and verification scripts. The wheel contains only
application packages and distribution metadata.

The verifier creates separate temporary environments for wheel and sdist, installs
hash-checked locked dependencies, installs each artifact without an editable
checkout, checks dependency consistency, runs CLI smoke tests, and runs pytest
against the installed package from outside the checkout. It checks all three help
commands, synthetic analysis, CE import, JSON/Markdown reports, and invalid input.
Repeat with `--python 3.11` to exercise the other supported interpreter. Initial
runs require network access to download Python, dependencies, or build tooling.

For a standalone installation without development dependencies:

```bash
uv venv --python 3.12 /tmp/pathlens-install
uv export --locked --no-dev --no-emit-project --output-file /tmp/pathlens-runtime.txt
uv pip install --python /tmp/pathlens-install/bin/python --require-hashes -r /tmp/pathlens-runtime.txt
uv pip install --python /tmp/pathlens-install/bin/python --no-deps dist/pathlens-0.1.0-py3-none-any.whl
/tmp/pathlens-install/bin/pathlens --help
```

Use a fresh destination for this example. On Windows, choose a temporary directory
and use its `Scripts/python.exe` and `Scripts/pathlens.exe` paths instead.

### Continuous integration and release status

`.github/workflows/ci.yml` runs on pushes, pull requests, and manual dispatch with
Python 3.11/3.12. It installs locked dependencies, runs pytest, builds both artifacts,
and verifies each in a separate environment. Permissions are `contents: read`;
checkout credentials are not persisted. Only GitHub's checkout and Python setup
actions are used, pinned to commit IDs. There is no publishing job or release token.

Release validation calls for a successful hosted CI run and authorized real
BloodHound export validation. Local workflow files alone do not establish those
results.
