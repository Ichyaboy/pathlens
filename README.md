# PathLens (starter MVP)

Deterministic, offline analysis of **synthetic** Active Directory-style relationship graphs.
This prototype does **not** import BloodHound exports yet and does not establish exploitability.

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
verified, or displayed by the CLI. Unknown schema fields and non-finite numbers
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

The layer does not evaluate ACLs, deny entries, inheritance, group scope, tokens,
attribute restrictions, or evidence authenticity. Preconditions are guidance to
validate, not findings. It does not infer new edges, perform transitive permission
composition, rank risk, or claim that a path is an executable attack chain.

## Limitations
- Only a custom JSON graph schema is supported.
- The shortest path minimizes graph hops, not exploit difficulty.
- Only one deterministic shortest node path is selected; alternative paths are not enumerated.
- Only six relationship labels have typed descriptive semantics.
- Graph relationships do not prove practical exploitability.
- Do not upload or publish real customer directory data.
