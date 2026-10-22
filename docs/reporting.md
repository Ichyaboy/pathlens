# Security reports

[← PathLens](../README.md)

Commands below run from the repository root.

The default `analyze` output remains the existing terminal view. Select a report
format explicitly to generate a standalone document:

```bash
.venv/bin/pathlens analyze --input data/sample_domain.json \
  --source ICHYABOY --target "DOMAIN ADMINS" --format markdown --output report.md
.venv/bin/pathlens analyze --input data/sample_domain.json \
  --source ICHYABOY --target "DOMAIN ADMINS" --format json --output report.json
```

Omit `--output` to emit only the report to stdout. Report-mode errors go to
stderr. `--output` requires `--format json` or `--format markdown`; terminal
output is not captured into a file implicitly. Existing paths, including input
files and symlinks, are never overwritten. Reports reuse the importer's atomic
no-overwrite writer and its [filesystem limitations](bloodhound.md#rejections-limits-and-output-safety). Analysis
and rendering complete before output publication. Missing endpoints or malformed
input return exit code `2`; disconnected paths and output I/O failures return
`1`. No report file is produced for unsuccessful analysis.

`pathlens.reporting.build_report(PathAnalysis)` creates a detached, typed
`AnalysisReport` snapshot. `render_json` and `render_markdown` render that same
model independently of the terminal formatter. The JSON schema version is `1`.
Both formats include endpoints, the selected node sequence, hop and relationship
counts, every parallel relationship per selected hop (including duplicates),
node types, descriptions, conditional implications, target compatibility and
diagnostics, prerequisites, limitations, defensive remediation, and reference
URLs. References document semantics; they are not evidence for an assertion.

Graph-level metadata and the selected nodes' and relationships' evidence and
provenance are included without promoting their contents into findings. The
report covers only the selected path, not all nodes and edges in the input.
Imported source records remain in their original provenance namespace. JSON
preserves missing metadata versus explicit `null`; Markdown shows original
assertion records as literal JSON and identifies absent graph metadata.

Reports explicitly separate input graph assertions, potential security
implications, and independently validated findings. The latter is always an empty
array with `validation_status: not_performed`; it is not a statement that the
environment is safe. Report and relationship exploitability remain `not_assessed`.
No severity, CVSS, or exploitation outcome is inferred. Unknown relationships
retain their assertions and unknown semantics, with no relationship-specific
remediation. Incompatible or unknown target compatibility suppresses applied
implications while retaining diagnostic and prerequisite guidance.

Output is deterministic for identical analysis data: path/relationship ordering
comes from graph analysis, JSON keys are sorted, and no timestamp is generated.
Reordered equivalent native graphs produce identical reports. Imported files
with different byte hashes or source record positions can differ in provenance.

Markdown uses fixed structural headings, entity-encoded dynamic prose, and
indented JSON code blocks for assertions and metadata. Untrusted HTML, Markdown
links/images, fences, or newlines cannot introduce report structure under
CommonMark. Control and non-ASCII characters are shown using JSON escapes to
make direction overrides and other invisible characters visible. JSON uses
standard serialization with non-finite values prohibited. Consumers embedding
JSON into HTML must still escape it for that context. Reports include supplied
metadata in full; they do not redact or authenticate it.
