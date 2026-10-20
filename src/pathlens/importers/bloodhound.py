"""Strict CE graph-view adapter. See README for the pinned export call chain."""

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from typing import NoReturn

from pydantic import JsonValue

from pathlens.graph import Edge, GraphData, Node
from pathlens.relationships import endpoint_warnings, lookup_relationship

UPSTREAM_REVISION = "41421cc5e28370e1feab7e454a032ba808c7cce1"
KNOWN_NODE_TYPES = {"User", "Group", "Computer", "OU", "Domain", "GPO", "Container"}


@dataclass(frozen=True)
class ImportLimits:
    max_bytes: int = 16 * 1024 * 1024
    max_depth: int = 64
    max_nodes: int = 50_000
    max_edges: int = 100_000


DEFAULT_LIMITS = ImportLimits()


class ImportValidationError(ValueError):
    """Invalid or unsupported source document; no output should be published."""


@dataclass(frozen=True)
class ImportResult:
    data: GraphData
    diagnostics: tuple[str, ...]


def _reject_constant(value: str) -> NoReturn:
    raise ImportValidationError(f"Non-finite JSON number: {value}")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        _reject_constant(value)
    return result


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ImportValidationError("Duplicate JSON object key")
        result[key] = value
    return result


def _check_depth(text: str, maximum: int) -> None:
    """Bound containers before recursive JSON decoding, respecting escaped strings."""
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > maximum:
                raise ImportValidationError(f"JSON nesting exceeds {maximum} levels")
        elif char in "]}":
            depth -= 1


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


def _optional_fields(record: dict[str, JsonValue], location: str) -> None:
    for field in ("label", "objectId", "lastSeen"):
        if field in record and not isinstance(record[field], str):
            raise ImportValidationError(f"{location}/{field}: expected a string")
    for field in ("isTierZero", "isOwnedObject", "hidden"):
        if field in record and not isinstance(record[field], bool):
            raise ImportValidationError(f"{location}/{field}: expected a boolean")
    if "properties" in record:
        _object(record["properties"], f"{location}/properties")
    if "kinds" in record:
        kinds = record["kinds"]
        if not isinstance(kinds, list) or any(not isinstance(kind, str) for kind in kinds):
            raise ImportValidationError(f"{location}/kinds: expected an array of strings")


def _canonical(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def parse_ce_graph(raw: bytes, limits: ImportLimits = DEFAULT_LIMITS) -> ImportResult:
    """Normalize one document, without network access or security inference."""
    if len(raw) > limits.max_bytes:
        raise ImportValidationError(f"Input exceeds {limits.max_bytes} bytes")
    try:
        text = raw.decode("utf-8")
        _check_depth(text, limits.max_depth)
        document = json.loads(
            text, object_pairs_hook=_unique_object,
            parse_constant=_reject_constant, parse_float=_finite_float,
        )
    except ImportValidationError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ImportValidationError("Invalid UTF-8 JSON document") from exc
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
    if len(nodes) > limits.max_nodes:
        raise ImportValidationError(f"Node count exceeds {limits.max_nodes}")
    if len(edges) > limits.max_edges:
        raise ImportValidationError(f"Edge count exceeds {limits.max_edges}")

    diagnostics = {"Scope: exported graph only; exploitability not assessed."}
    normalized_nodes: list[Node] = []
    normalized_edges: list[Edge] = []
    node_types: dict[str, str] = {}
    node_fields = {"kind", "kinds", "label", "objectId", "lastSeen", "properties",
                   "isTierZero", "isOwnedObject", "hidden"}
    edge_fields = {"id", "kind", "label", "source", "target", "lastSeen", "properties"}
    if root.keys() - {"nodes", "edges", "literals", "node_keys", "edge_keys"}:
        diagnostics.add("Additional graph fields retained without interpretation.")
    for key, value in sorted(nodes.items()):
        location = f"/nodes/{_pointer(key)}"
        _identifier(key, location)
        record = _object(value, location)
        kind = _identifier(record.get("kind"), f"{location}/kind")
        _optional_fields(record, location)
        node_types[key] = kind
        if kind not in KNOWN_NODE_TYPES:
            diagnostics.add(f"Unknown node type {kind!r} retained.")
        if record.keys() - node_fields:
            diagnostics.add("Additional node fields retained without interpretation.")
        normalized_nodes.append(Node(
            id=f"bhce:{key}", type=kind,
            provenance={"bloodhound": {"source_location": location, "record": record}},
        ))

    seen_ids: dict[str, str] = {}
    for index, value in enumerate(edges):
        location = f"/edges/{index}"
        record = _object(value, location)
        source = _identifier(record.get("source"), f"{location}/source")
        target = _identifier(record.get("target"), f"{location}/target")
        kind = _identifier(record.get("kind"), f"{location}/kind")
        edge_id = _identifier(record.get("id"), f"{location}/id")
        _optional_fields(record, location)
        for field, endpoint in (("source", source), ("target", target)):
            if endpoint not in nodes:
                raise ImportValidationError(f"{location}/{field}: dangling node reference")
        canonical = _canonical(record)
        if edge_id in seen_ids:
            if seen_ids[edge_id] != canonical:
                raise ImportValidationError(f"{location}/id: conflicting records share an edge ID")
            diagnostics.add("Identical repeated edge records retained separately.")
        seen_ids[edge_id] = canonical
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
            provenance={"bloodhound": {"source_location": location, "record": record}},
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
    with path.open("rb") as stream:
        raw = stream.read(limits.max_bytes + 1)
    return parse_ce_graph(raw, limits)


def serialize_graph(data: GraphData) -> str:
    return json.dumps(
        data.model_dump(exclude_unset=True), sort_keys=True,
        ensure_ascii=True, allow_nan=False, indent=2,
    ) + "\n"


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
