"""Strict CE graph-view adapter. See README for the pinned export call chain."""

from dataclasses import dataclass
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import tempfile

from pydantic import JsonValue

from pathlens.graph import Edge, GraphData, Node
from pathlens.json_input import (
    InputLimits as ImportLimits, InputValidationError as ImportValidationError,
    NATIVE_LIMITS, check_counts, check_depth, parse_json, read_bytes,
)
from pathlens.relationships import endpoint_warnings, lookup_relationship

UPSTREAM_REVISION = "41421cc5e28370e1feab7e454a032ba808c7cce1"
KNOWN_NODE_TYPES = {"User", "Group", "Computer", "OU", "Domain", "GPO", "Container"}


DEFAULT_LIMITS = ImportLimits()


@dataclass(frozen=True)
class ImportResult:
    data: GraphData
    diagnostics: tuple[str, ...]


def _object(value: JsonValue, location: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ImportValidationError(f"{location}: expected an object")
    return value


def _identifier(value: JsonValue, location: str) -> str:
    if (
        not isinstance(value, str) or not value.strip()
        or value != value.strip()
        or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    ):
        raise ImportValidationError(f"{location}: expected a nonempty string without surrounding whitespace or control characters")
    return value


def _pointer(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _optional_fields(record: dict[str, JsonValue], location: str, *, node: bool) -> None:
    for field in (("label", "objectId", "lastSeen") if node else ("label", "lastSeen")):
        if field in record and not isinstance(record[field], str):
            raise ImportValidationError(f"{location}/{field}: expected a string")
    for field in (("isTierZero", "isOwnedObject", "hidden") if node else ()):
        if field in record and not isinstance(record[field], bool):
            raise ImportValidationError(f"{location}/{field}: expected a boolean")
    if "properties" in record:
        _object(record["properties"], f"{location}/properties")
    if node and "kinds" in record:
        kinds = record["kinds"]
        if not isinstance(kinds, list) or any(not isinstance(kind, str) for kind in kinds):
            raise ImportValidationError(f"{location}/kinds: expected an array of strings")


def _canonical(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def parse_ce_graph(raw: bytes, limits: ImportLimits = DEFAULT_LIMITS) -> ImportResult:
    """Normalize one document, without network access or security inference."""
    document = parse_json(raw, limits)
    root = _object(document, "/")
    if "data" in root and "meta" in root:
        raise ImportValidationError("Unsupported collector JSON (data/meta); expected a CE graph-view export")
    if isinstance(root.get("nodes"), list):
        raise ImportValidationError("Unsupported node-array format (including legacy graph exports)")
    if "data" in root:
        raise ImportValidationError("Unsupported wrapped/API response; expected an unwrapped CE graph-view export")
    nodes = _object(root.get("nodes"), "/nodes")
    edges = root.get("edges")
    if not isinstance(edges, list):
        raise ImportValidationError("/edges: expected an array")
    check_counts(len(nodes), len(edges), limits)

    diagnostics = {"Scope: exported graph only; exploitability not assessed."}
    normalized_nodes: list[Node] = []
    normalized_edges: list[Edge] = []
    node_types: dict[str, str] = {}
    node_fields = {"kind", "kinds", "label", "objectId", "lastSeen", "properties",
                   "isTierZero", "isOwnedObject", "hidden"}
    edge_fields = {"id", "exploreGraphId", "data", "kind", "label", "source", "target",
                   "lastSeen", "properties"}
    if root.keys() - {"nodes", "edges", "literals", "node_keys", "edge_keys"}:
        diagnostics.add("Additional graph fields retained without interpretation.")
    for key, value in sorted(nodes.items()):
        location = f"/nodes/{_pointer(key)}"
        _identifier(key, location)
        record = _object(value, location)
        kind = _identifier(record.get("kind"), f"{location}/kind")
        _optional_fields(record, location, node=True)
        node_types[key] = kind
        if kind not in KNOWN_NODE_TYPES:
            diagnostics.add(f"Unknown node type {kind!r} retained.")
        if record.keys() - node_fields:
            diagnostics.add("Additional node fields retained without interpretation.")
        normalized_nodes.append(Node(
            id=f"bhce:{key}", type=kind,
            provenance={"bloodhound": {"source_location": location, "record": record}},
        ))

    seen_ids: set[str] = set()
    for index, value in enumerate(edges):
        location = f"/edges/{index}"
        record = _object(value, location)
        source = _identifier(record.get("source"), f"{location}/source")
        target = _identifier(record.get("target"), f"{location}/target")
        kind = _identifier(record.get("kind"), f"{location}/kind")
        # Both spellings identify an export-local relationship, never a global ID.
        id_field = "exploreGraphId" if "exploreGraphId" in record else "id"
        edge_id = _identifier(record.get(id_field), f"{location}/{id_field}")
        if "exploreGraphId" in record and "id" in record:
            legacy_id = _identifier(record["id"], f"{location}/id")
            if legacy_id != edge_id:
                raise ImportValidationError(f"{location}: conflicting id and exploreGraphId")
        _optional_fields(record, location, node=False)
        for field, endpoint in (("source", source), ("target", target)):
            if endpoint not in nodes:
                raise ImportValidationError(f"{location}/{field}: dangling node reference")
        if edge_id in seen_ids:
            raise ImportValidationError(f"{location}/{id_field}: duplicate edge ID")
        seen_ids.add(edge_id)
        if "label" in record and record["label"] != kind:
            diagnostics.add("Edge label differs from kind; kind used, both retained.")
        if record.keys() - edge_fields:
            diagnostics.add("Additional edge fields retained without interpretation.")
        semantics = lookup_relationship(kind)
        if semantics is None:
            diagnostics.add(f"Unknown relationship {kind!r} retained; semantics unknown.")
        diagnostics.update(endpoint_warnings(semantics, node_types[target]))
        normalized_edges.append(Edge(
            source=f"bhce:{source}", target=f"bhce:{target}", relation=kind,
            provenance={"bloodhound": {
                "source_location": location, "record": record,
                "edge_id": edge_id, "edge_id_field": id_field,
                "identity_scope": "export_local",
            }},
        ))
    normalized_edges.sort(key=lambda edge: (
        edge.source, edge.target, edge.relation, _canonical(edge.provenance),
    ))
    data = GraphData(
        nodes=normalized_nodes, edges=normalized_edges,
        provenance={
            "pathlens_import": {
                "adapter": "ce-graph-v1", "upstream_revision": UPSTREAM_REVISION,
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "scope": "exported_graph_only",
            },
            "bloodhound": {key: value for key, value in root.items() if key not in {"nodes", "edges"}},
        },
    )
    return ImportResult(data=data, diagnostics=tuple(sorted(diagnostics)))


def read_ce_graph(path: Path, limits: ImportLimits = DEFAULT_LIMITS) -> ImportResult:
    return parse_ce_graph(read_bytes(path, limits), limits)


def serialize_graph(data: GraphData) -> str:
    # Bound accumulated output too: indentation can greatly expand nested metadata.
    check_counts(len(data.nodes), len(data.edges), NATIVE_LIMITS)
    encoder = json.JSONEncoder(sort_keys=True,
        ensure_ascii=True, allow_nan=False, indent=2,
    )
    with StringIO() as stream:
        length = 1  # final newline; ensure_ascii makes chars == bytes
        for chunk in encoder.iterencode(data.model_dump(exclude_unset=True)):
            length += len(chunk)
            if length > NATIVE_LIMITS.max_bytes:
                raise ImportValidationError("Normalized output exceeds native input byte limit")
            stream.write(chunk)
        stream.write("\n")
        content = stream.getvalue()
    # Never publish normalization that the default native reader cannot accept.
    check_depth(content, NATIVE_LIMITS.max_depth)
    return content


def write_new_file(path: Path, content: str) -> None:
    """Publish a complete file atomically; link fails if any destination exists.

    Requires same-filesystem hard-link support. Never fall back to replacement.
    Only the private temporary file created here is removed.
    """
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".pathlens-", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink()
