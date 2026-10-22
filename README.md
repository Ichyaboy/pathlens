# PathLens

Explain Active Directory graph paths with offline analysis and conditional remediation guidance.

A graph path shows relationships; assessing what they mean requires context.
PathLens complements BloodHound by importing supported CE Explore JSON exports,
explaining a selected path, and producing reports for penetration testers, red
teams, and defenders.

**Alpha:** graph paths are not proof of exploitability. PathLens does not query
Active Directory or independently validate permissions.

## Features

- Deterministic shortest directed paths, preserving parallel relationships.
- Explanations, prerequisites, limitations, and remediation for six relationship
  types; unknown types remain visible.
- Terminal analysis plus JSON and Markdown reports with original provenance.
- Bounded JSON validation and atomic file output that never overwrites existing files.

## Install and try

Requires **CPython 3.11 or 3.12** and [uv](https://docs.astral.sh/uv/getting-started/installation/).
From the repository root:

```bash
uv sync --locked --extra dev --python 3.12
uv run --no-sync pathlens analyze --input data/sample_domain.json \
  --source ICHYABOY --target "DOMAIN ADMINS"
```

Selected lines from the bundled synthetic example:

```text
PathLens v0.1 — 3 relationships
[1] ICHYABOY -> HELPDESK (MemberOf)
[2] HELPDESK -> IT-ADMINS (GenericAll)
[3] IT-ADMINS -> DOMAIN ADMINS (MemberOf)
Exploitability: not assessed.
```

Save a Markdown report, including relationship guidance and provenance:

```bash
uv run --no-sync pathlens analyze --input data/sample_domain.json \
  --source ICHYABOY --target "DOMAIN ADMINS" \
  --format markdown --output report.md
```

Use `--format json` for structured output. Choose a new output filename on each run.

## Import a BloodHound graph

Try the synthetic Explore fixture (9 nodes, 23 relationships):

```bash
uv run --no-sync pathlens import bloodhound \
  --input tests/fixtures/bloodhound/ce_explore_graph.json --output normalized.json
uv run --no-sync pathlens analyze --input normalized.json \
  --source bhce:1 --target bhce:2
```

For your own export, use its graph-local node IDs prefixed with `bhce:`.
See the [supported export schema](docs/bloodhound.md#accepted-schema-and-normalization).

## Scope and limitations

- Supports the documented CE graph export shape, not SharpHound collector files
  or every BloodHound format.
- Selects one shortest path by hop count, not exploit difficulty; missing paths
  describe only the supplied graph.
- Models six relationship labels. Guidance is conditional; exploitability remains
  `not_assessed`.
- Reports retain supplied metadata without redaction. Use synthetic or authorized
  data and keep customer directory data out of public issues and contributions.

## Documentation and contributing

- [BloodHound import](docs/bloodhound.md) — schema, identity, provenance, and limits.
- [Analysis and relationship semantics](docs/analysis.md) — path selection and interpretation.
- [Reports](docs/reporting.md) — formats, metadata, and output safety.
- [Development](docs/development.md) — setup, tests, packaging, and CI.

Keep contributions focused, include regression tests for behavior changes, and
use synthetic fixtures. Follow [AGENTS.md](AGENTS.md) and run
`uv run --no-sync python -m pytest -q` before submitting changes.

Licensed under [Apache 2.0](LICENSE).
