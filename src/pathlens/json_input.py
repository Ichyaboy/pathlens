"""Bounded, strict JSON decoding shared by native graphs and offline adapters."""

from dataclasses import dataclass
import json
import math
from pathlib import Path
from typing import NoReturn

from pydantic import JsonValue


class InputValidationError(ValueError):
    """Safe diagnostic containing no source values or metadata."""


@dataclass(frozen=True)
class InputLimits:
    max_bytes: int = 16 * 1024 * 1024
    max_depth: int = 64
    max_nodes: int = 50_000
    max_edges: int = 100_000

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 1 for value in (
            self.max_bytes, self.max_depth,
        )) or any(type(value) is not int or value < 0 for value in (
            self.max_nodes, self.max_edges,
        )):
            raise ValueError("Input limits must be integers with positive byte/depth limits and nonnegative record limits")


# Normalization adds provenance containers and expands source records/JSON escapes.
NATIVE_LIMITS = InputLimits(max_bytes=64 * 1024 * 1024, max_depth=72)


def _reject_constant(_value: str) -> NoReturn:
    raise InputValidationError("Non-finite JSON number")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        _reject_constant(value)
    return result


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise InputValidationError("Duplicate JSON object key")
        result[key] = value
    return result


def check_depth(text: str, maximum: int) -> None:
    """Check before recursive decoding, ignoring brackets within JSON strings."""
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
                raise InputValidationError(f"JSON nesting exceeds {maximum} levels")
        elif char in "]}":
            depth -= 1


def check_counts(nodes: int, edges: int, limits: InputLimits) -> None:
    if nodes > limits.max_nodes:
        raise InputValidationError(f"Node count exceeds {limits.max_nodes}")
    if edges > limits.max_edges:
        raise InputValidationError(f"Edge count exceeds {limits.max_edges}")


def read_bytes(path: Path, limits: InputLimits) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(limits.max_bytes + 1)
    if len(raw) > limits.max_bytes:
        raise InputValidationError(f"Input exceeds {limits.max_bytes} bytes")
    return raw


def parse_json(raw: bytes, limits: InputLimits) -> JsonValue:
    if len(raw) > limits.max_bytes:
        raise InputValidationError(f"Input exceeds {limits.max_bytes} bytes")
    try:
        text = raw.decode("utf-8")
        check_depth(text, limits.max_depth)
        return json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant, parse_float=_finite_float)
    except InputValidationError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise InputValidationError("Invalid UTF-8 JSON document") from None
