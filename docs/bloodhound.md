# Offline BloodHound CE import

[← PathLens](../README.md)

Commands below run from the repository root.

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
The checked-in fixtures are synthetic, not organizational exports.
`ce_explore_graph.json` models the reported Explore shape with 9 nodes and
23 edges. These checked-in fixtures do not establish validation against a real
organizational export.

### Verified export boundary

The `ce-graph-v1` adapter is based on BloodHound revision
`41421cc5e28370e1feab7e454a032ba808c7cce1`. This is a PathLens adapter profile,
not an upstream version field or a promise to support all CE releases.
The previous importer documentation records inspection of this UI download
call chain:

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
That documented verification used source inspection, not a live browser capture.

### Accepted schema and normalization

| Record | Required fields | Optional typed fields |
| --- | --- | --- |
| Root | `nodes`: object keyed by graph-local IDs; `edges`: array | Other root fields are retained opaquely, including `literals`, `node_keys`, `edge_keys` |
| Node | `kind`: nonempty string | `label`, `objectId`, `lastSeen`: strings; `kinds`: string array; `properties`: object; `isTierZero`, `isOwnedObject`, `hidden`: booleans |
| Edge | `exploreGraphId` (or legacy `id`), `source`, `target`, `kind`: nonempty strings | `label`, `lastSeen`: strings; `properties`: object; `data`: opaque JSON |

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

Every accepted edge record survives, including parallel edges with distinct IDs
and self-loops. Isolated nodes remain present. All duplicate edge IDs are rejected,
even for identical records (a deliberate tightening of the previous contract).
Explore `exploreGraphId` values such as `rel_1183` use the same string validation
as legacy `id`; no prefix pattern or cross-export stability is assumed. If both
fields appear, both must be valid and equal. Uniqueness is checked across the
entire export, including mixed ID spellings and different endpoint pairs.
The selected `edge_id`, `edge_id_field`, and `identity_scope: export_local` are
retained in edge provenance; NetworkX keys remain internal multigraph keys.
Edge `data` is retained without imposing an undocumented internal schema or
interpreting its contents as evidence of exploitability. Unknown node and
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
