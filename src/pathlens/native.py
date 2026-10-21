"""Native graph input and value-free schema diagnostics."""

from pathlib import Path

from pydantic import ValidationError

from pathlens.graph import GraphData
from pathlens.json_input import (
    InputLimits, InputValidationError, NATIVE_LIMITS, check_counts, parse_json, read_bytes,
)


def validation_summary(exc: ValidationError) -> str:
    """Expose structural paths/categories, never values, custom messages or metadata keys."""
    summaries = []
    fields = {"id", "type", "source", "target", "relation", "evidence", "provenance"}
    for error in exc.errors(include_input=False, include_context=False, include_url=False)[:10]:
        loc = error["loc"]
        path = "/"
        if loc and loc[0] in {"nodes", "edges"}:
            path += loc[0]
            if len(loc) > 1 and isinstance(loc[1], int):
                path += f"/{loc[1]}"
                if len(loc) > 2:
                    path += "/" + (loc[2] if loc[2] in fields else "<field>")
        elif loc:
            path += loc[0] if loc[0] in {"evidence", "provenance"} else "<field>"
        summaries.append(f"{path}: {error['type']}")
    return "; ".join(summaries)


def parse_native_graph(raw: bytes, limits: InputLimits = NATIVE_LIMITS) -> GraphData:
    document = parse_json(raw, limits)
    if not isinstance(document, dict):
        raise InputValidationError("/: expected an object")
    for field in ("nodes", "edges"):
        if not isinstance(document.get(field), list):
            raise InputValidationError(f"/{field}: expected an array")
    check_counts(len(document["nodes"]), len(document["edges"]), limits)
    try:
        return GraphData.model_validate(document)
    except ValidationError as exc:
        raise InputValidationError(validation_summary(exc)) from None
    except RecursionError:
        raise InputValidationError("JSON nesting exceeds supported validation depth") from None


def read_native_graph(path: Path, limits: InputLimits = NATIVE_LIMITS) -> GraphData:
    return parse_native_graph(read_bytes(path, limits), limits)
