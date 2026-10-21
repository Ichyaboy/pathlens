# PathLens (starter MVP)

Deterministic, offline analysis of **synthetic** Active Directory-style relationship graphs.
Includes a bounded offline importer for one BloodHound CE graph-export profile.
This prototype does not establish exploitability.

## Run

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\pathlens.exe analyze --input data/sample_domain.json --source ICHYABOY --target "DOMAIN ADMINS"
.\.venv\Scripts\python.exe -m pytest -q
```

For Linux/macOS:

```bash
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/pathlens analyze --input data/sample_domain.json --source ICHYABOY --target "DOMAIN ADMINS"
.venv/bin/python -m pytest -q
```

## Graph analysis

`pathlens.graph` validates input, builds a NetworkX `MultiDiGraph`, and provides
`shortest_node_path` and `analyze_graph`. Relationships remain directed, parallel
relationships (including duplicates) are retained, and isolated nodes are kept.

Path selection minimizes the number of directed node-to-node hops. Among tied
shortest paths, it selects the lexicographically smallest complete sequence of
node IDs using Python's case-sensitive Unicode string order (no normalization
or locale-specific comparison). Sorted-successor breadth-first traversal makes
this independent of input node and edge ordering. A node's path to itself has
zero hops.

Traversal uses O(V + sum(d(v) log(max(2, d(v))))) time and O(V) auxiliary
space, where d(v) counts distinct successors, not parallel edges. These are
worst-case bounds over the reachable subgraph, assuming constant-cost string
comparisons. It stores one parent per visited node and never enumerates all
shortest paths. Graph storage still includes every edge and its metadata.
For k parallel records on a reported hop, sorting costs O(k log k) key
comparisons plus JSON serialization; long metadata keys also increase comparison
and memory costs. Graph construction and analysis additionally copy metadata.

For every selected hop, all parallel relationships are reported, sorted first
by relationship name and then by the complete relationship record serialized as
JSON with sorted keys and ASCII escaping. Exact duplicates remain separate.
CLI brackets identify the hop; the header counts all displayed relationships,
which can exceed the hop count.

The graph object, nodes, and edges may each contain optional `evidence` and
`provenance` fields holding arbitrary JSON values. Supplied values are retained
through validation, graph construction, and structured analysis results.
Omission stays distinct from explicit `null`; use `model_dump(exclude_unset=True)`
on result nodes and edges to retain that distinction. Metadata is not inferred,
verified, or displayed by the default terminal view. Structured reports include
available metadata. Unknown schema fields and non-finite numbers
are rejected rather than silently discarded.

Unknown relationship names are retained and explicitly reported as
**unrecognized**, with no security conclusion. Recognition means an exact label match, not verified permissions.

## Milestone 3: typed relationship semantics

`pathlens.relationships` provides `RelationshipKind`, `RelationshipCategory`, and
immutable `RelationshipSemantics` definitions through `lookup_relationship`.
Each `RelationshipReport` exposes `semantics` (or `None` for unknown labels)
and a tuple of `warnings`, alongside the unchanged original `edge` record.
`pathlens.semantics` retains compatibility imports for existing callers.
Definitions include applicable target types, potential implications,
prerequisites to validate, limitations, remediation guidance,
and documentation references. Those references describe semantics; they are not
collector provenance or evidence for any supplied edge.

| Label | Category | Input assertion |
| --- | --- | --- |
| MemberOf | membership | Source is a member of the target group. |
| GenericAll | permission | Source has GenericAll rights over the target directory object. |
| GenericWrite | permission | Source has GenericWrite rights over the target directory object. |
| AddMember | permission | Source can modify the target group's member attribute. |
| WriteDacl | permission | Source can modify the target object's DACL. |
| WriteOwner | permission | Source can change the owner in the target object's security descriptor. |

`AddMember` is a convention of this custom schema, not a Windows access-mask
name. Permission descriptions follow [Microsoft AD access rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584);
membership context follows [Microsoft group objects](https://learn.microsoft.com/en-us/windows/win32/ad/group-objects).

For MemberOf and AddMember, a target type other than exactly `Group` produces
an interpretation warning. The relationship remains recognized and retained;
the warning does not change path selection, input acceptance, or exit codes.
Compatibility is explicitly `compatible`, `incompatible`, or `unknown`.
For permission labels other than AddMember, known directory target labels are
`User`, `Group`, `Computer`, `OU`, `Domain`, `GPO`, and `Container`; this list is
not an exhaustive directory schema. Other labels have unknown compatibility.
MemberOf and AddMember are incompatible with known non-Group types; unfamiliar
types have unknown compatibility. Node types and relation labels remain raw
strings; unknown values are never normalized into known types.

The report separates the observed input `edge` from `potential_implications`
and `exploitability`. Potential implications are conditional guidance and are
only applied to compatible target types. Both edge and path exploitability are
always `not_assessed`, even when supplied evidence claims successful exploitation.
Compatibility does not validate the object class or effective permissions.
Unknown relationship labels have `semantics_status="unknown"`, no definition,
and no applied implications. Traversal consults only directed graph topology,
never relationship recognition, compatibility, or implications.

The CLI prints descriptions, conditional implications, guidance, and warnings
using literal text, without printing metadata. Syntax and exit codes are unchanged.
Terminal text escapes ASCII/C1 controls, ANSI escape introducers, Unicode format
and bidi controls, surrogates, and line separators. Original strings remain
unchanged in structured data. Validation errors report structural field paths
and categories rather than rejected values, metadata keys, or complete records.
I/O errors report their exception category and errno without echoing filenames.

Native analysis and CE import share a strict, bounded UTF-8 JSON decoder.
Duplicate keys at every depth, non-finite numbers (including overflow), and
malformed or excessively nested JSON are rejected with exit code `2`.
Schema fields are type-checked without coercion. Native input defaults to
**64 MiB, 72 nested containers, 50,000 nodes, and 100,000 edges**; CE input
retains the smaller limits below. The native allowance accommodates imported
provenance and escaped Unicode. Python callers can use `read_native_graph` or
`parse_native_graph` from `pathlens.native` with an `InputLimits` instance.
Direct construction of `GraphData` does not apply file byte or record limits.

The layer does not evaluate ACLs, deny entries, inheritance, group scope, tokens,
attribute restrictions, or evidence authenticity. Preconditions are guidance to
validate, not findings. It does not infer new edges, perform transitive permission
composition, rank risk, or claim that a path is an executable attack chain.

## Security reports

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
no-overwrite writer and its filesystem limitations described below. Analysis
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

## Offline BloodHound CE import

```bash
.venv/bin/pathlens import bloodhound \
  --input tests/fixtures/bloodhound/ce_graph.json \
  --format ce-graph --output normalized.json
.venv/bin/pathlens analyze --input normalized.json \
  --source bhce:101 --target bhce:205
```

Omit `--output` to write normalized JSON to stdout. Diagnostics and the import
summary go to stderr. `--format` defaults to `ce-graph`; no other format is
supported. The importer runs entirely offline and adds no dependencies.
The checked-in fixture is synthetic, not an organizational export.

### Verified export boundary

The `ce-graph-v1` adapter is based on BloodHound revision
`41421cc5e28370e1feab7e454a032ba808c7cce1`. This is a PathLens adapter profile,
not an upstream version field or a promise to support all CE releases.
The actual UI download call chain was inspected:

1. [GraphView](https://github.com/SpecterOps/BloodHound/blob/41421cc5e28370e1feab7e454a032ba808c7cce1/cmd/ui/src/views/Explore/GraphView.tsx)
   passes `graphQuery.data` from `useSigmaExploreGraph` to `GraphControls.jsonData`.
2. [useSigmaExploreGraph](https://github.com/SpecterOps/BloodHound/blob/41421cc5e28370e1feab7e454a032ba808c7cce1/cmd/ui/src/hooks/useSigmaExploreGraph/useSigmaExploreGraph.tsx)
   unwraps `GraphResponse.data`; a separate branch transforms flat responses.
3. [GraphControls](https://github.com/SpecterOps/BloodHound/blob/41421cc5e28370e1feab7e454a032ba808c7cce1/packages/javascript/bh-shared-ui/src/components/GraphControls/GraphControls.tsx)
   calls `exportToJson(jsonData)` for Export → JSON.
4. [exportGraphData](https://github.com/SpecterOps/BloodHound/blob/41421cc5e28370e1feab7e454a032ba808c7cce1/packages/javascript/bh-shared-ui/src/utils/exportGraphData.ts)
   downloads `JSON.stringify(data)` without an envelope.

Thus support is for the **unwrapped node-map/edge-array shape**, grounded in
the UI call chain as well as the
[UnifiedGraph representation](https://github.com/SpecterOps/BloodHound/blob/41421cc5e28370e1feab7e454a032ba808c7cce1/cmd/api/src/model/unified_graph.go).
Flat-response exports are accepted only if their resulting downloaded shape
meets this exact contract; no flat-response or arbitrary table adapter exists.
Verification used source inspection, not a live browser capture.

### Accepted schema and normalization

| Record | Required fields | Optional typed fields |
| --- | --- | --- |
| Root | `nodes`: object keyed by graph-local IDs; `edges`: array | Other root fields are retained opaquely, including `literals`, `node_keys`, `edge_keys` |
| Node | `kind`: nonempty string | `label`, `objectId`, `lastSeen`: strings; `kinds`: string array; `properties`: object; `isTierZero`, `isOwnedObject`, `hidden`: booleans |
| Edge | `id`, `source`, `target`, `kind`: nonempty strings | `label`, `lastSeen`: strings; `properties`: object |

Node keys and required edge fields reject surrounding whitespace, ASCII control
characters, DEL, and unpaired surrogate characters. Numeric or Boolean IDs are
not coerced. Optional string fields may be empty. Missing optional fields stay
missing; explicit null is allowed in opaque metadata, but not in typed optional
fields. `lastSeen` is retained as a string without timestamp interpretation.
Extra record fields are retained with a diagnostic, not silently dropped.
Node-specific optional fields are validated only on nodes; fields with the same
names on edges are retained as opaque extensions.

Node keys become `bhce:<original-key>`. Edge endpoints resolve exclusively against
those keys. `objectId` and display names never merge identities. IDs are local to
one export; cross-file merging is unsupported. Node `kind` becomes `type`, and
edge `kind` becomes `relation`, with no spelling normalization or inference from
labels. Differing edge labels produce a warning and remain preserved.

Every edge record survives, including exact duplicates, parallel edges, and
self-loops. Isolated nodes remain present. Conflicting records sharing one edge
ID are rejected; identical repeats are retained with a warning. Unknown node and
relationship kinds are retained with diagnostics. Existing semantics apply
only as conditional descriptions, not validated directory facts.

Original parsed node/edge records and escaped JSON-pointer locations live under
`provenance.bloodhound`. Other root fields live under the graph's
`provenance.bloodhound`. Generated adapter identity, pinned revision, input-byte
SHA-256, and `exported_graph_only` scope live under `provenance.pathlens_import`.
Source evidence/provenance fields remain inside the original records; they are
not promoted into verified findings. No normalized evidence or import time is
invented. Whitespace and original JSON key order are not retained; the input
hash identifies the original bytes.

Nodes and edges are sorted deterministically. Identical input bytes produce
identical output. Reordering a graph preserves topology and shortest-node-path
selection; byte hashes and original record locations will differ.

### Rejections, limits, and output safety

Unsupported: SharpHound collector `data`/`meta` JSON, legacy node-array/Sigma
exports (including folded graphs), API wrappers, arbitrary query tables,
OpenGraph ingestion envelopes, archives, and directory inputs.
The adapter never reconstructs relationships from collector properties.

Malformed UTF-8/JSON, duplicate JSON object keys at any depth, NaN, infinities
(including numeric overflow such as `1e400`), dangling references, and invalid
required fields fail the whole import. Errors identify record locations when
available. There is no partial-import option.

Default limits: **16 MiB input bytes, 64 nested containers, 50,000 nodes,
100,000 edges**. The file reader reads at most the byte limit plus one; nesting
is checked before recursive JSON decoding. Record limits are checked after
bounded decoding and before normalization. These are input limits, not a
guarantee of a particular peak memory usage. Python callers may supply an
`ImportLimits` instance; the CLI uses fixed defaults.

All validation and serialization finish before stdout or file publication.
Normalized output must also fit the native byte, depth, and record limits;
otherwise import fails with exit code `2` before publishing anything. Thus every
successful CLI normalization is within the default native reader's limits,
even when provenance or ASCII escaping expands the original export.
File output uses a private temporary file in the destination directory,
flush/fsync, and atomic hard-link creation. It never replaces existing paths,
including symlinks, even if another writer creates the destination concurrently.
Temporary files are cleaned up on handled failures. Filesystems without hard-link
support fail explicitly; there is no unsafe fallback. A process crash may leave
a temporary file; power-loss durability of directory entries is not guaranteed.
Output files inherit the private temporary file's restrictive permissions.

Import exit codes: `0` success (including warnings), `2` invalid/unsupported
input or format, `1` I/O failure. Existing `analyze` exit codes remain unchanged.

Exports may omit query-filtered nodes, original ACL evidence, collector details,
or prerequisites behind derived relationships. `lastSeen` is not a verified
collection time: upstream formatting can supply a default. No-path results
apply only to the exported graph. Neither source assertions nor claims embedded
in evidence can change exploitability from `not_assessed`.

## Limitations
- Analysis uses the custom JSON schema; import supports only the CE profile above.
- The shortest path minimizes graph hops, not exploit difficulty.
- Only one deterministic shortest node path is selected; alternative paths are not enumerated.
- Only six relationship labels have typed descriptive semantics.
- Graph relationships do not prove practical exploitability.
- Do not upload or publish real customer directory data.
