"""Typed, evidence-conscious reports independent of terminal rendering."""

from copy import deepcopy
from dataclasses import asdict, dataclass, field
import json
import string
from typing import Literal

from pydantic import BaseModel, JsonValue

from pathlens.graph import Edge, Node, PathAnalysis
from pathlens.relationships import SemanticsStatus, TargetCompatibility


@dataclass(frozen=True)
class ReportRelationship:
    assertion: Edge
    description: str
    semantics_status: SemanticsStatus
    target_compatibility: TargetCompatibility
    diagnostics: tuple[str, ...]
    potential_implications: tuple[str, ...]
    prerequisites: tuple[str, ...]
    limitations: tuple[str, ...]
    remediation: str | None
    references: tuple[str, ...]
    exploitability: Literal["not_assessed"] = field(default="not_assessed", init=False)


@dataclass(frozen=True)
class ReportHop:
    number: int
    source: str
    target: str
    relationships: tuple[ReportRelationship, ...]


@dataclass(frozen=True)
class AnalysisReport:
    source: str
    target: str
    selected_path: tuple[str, ...]
    hop_count: int
    relationship_count: int
    nodes: tuple[Node, ...]
    hops: tuple[ReportHop, ...]
    graph_metadata: dict[str, JsonValue]
    schema_version: Literal["1"] = field(default="1", init=False)
    exploitability: Literal["not_assessed"] = field(default="not_assessed", init=False)
    independently_validated_findings: tuple[()] = field(default=(), init=False)
    validation_status: Literal["not_performed"] = field(default="not_performed", init=False)
    scope: str = field(default=(
        "One selected shortest directed node path in the supplied graph. "
        "Node and relationship records, including imported records and metadata, "
        "are input assertions, not independently validated findings. "
        "Potential implications are conditional guidance. "
        "A graph path is not proof of exploitability."
    ), init=False)


def build_report(analysis: PathAnalysis) -> AnalysisReport:
    """Snapshot a successful analysis, without promoting evidence to findings."""
    if not analysis.nodes:
        raise ValueError("A successful path analysis must contain at least one node")
    path = tuple(node.id for node in analysis.nodes)
    if len(analysis.relationships) != len(path) - 1:
        raise ValueError("Path and relationship hops disagree")
    hops = []
    for number, reports in enumerate(analysis.relationships, 1):
        relationships = []
        for report in reports:
            semantics = report.semantics
            relationships.append(ReportRelationship(
                assertion=report.edge.model_copy(deep=True),
                description=report.explanation,
                semantics_status=report.semantics_status,
                target_compatibility=report.target_compatibility,
                diagnostics=report.warnings,
                potential_implications=report.potential_implications,
                prerequisites=semantics.prerequisites if semantics else (),
                limitations=semantics.limitations if semantics else (
                    "Relationship semantics are unknown; no security conclusion is available.",
                ),
                remediation=semantics.remediation if semantics else None,
                references=semantics.references if semantics else (),
            ))
        hops.append(ReportHop(number, path[number - 1], path[number], tuple(relationships)))
    return AnalysisReport(
        source=path[0], target=path[-1], selected_path=path,
        hop_count=len(hops), relationship_count=sum(len(h.relationships) for h in hops),
        nodes=tuple(node.model_copy(deep=True) for node in analysis.nodes),
        hops=tuple(hops), graph_metadata=deepcopy(analysis.metadata),
    )


def _json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(exclude_unset=True)
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def _json(value: object) -> str:
    return json.dumps(value, default=_json_default, sort_keys=True,
                      ensure_ascii=True, allow_nan=False, indent=2)


def render_json(report: AnalysisReport) -> str:
    return _json(asdict(report)) + "\n"


def _text(value: str) -> str:
    """CommonMark literal text: entities cannot introduce Markdown/HTML syntax.

    JSON escaping makes newlines, control characters, and Unicode direction
    overrides visible instead of allowing them to alter report structure.
    """
    visible = json.dumps(value, ensure_ascii=True)[1:-1]
    return "".join(f"&#{ord(char)};" if char in string.punctuation else char for char in visible)


def _record(value: object) -> list[str]:
    # Indented code cannot be closed by backticks/HTML inside source metadata.
    return ["    " + line for line in _json(value).splitlines()] + [""]


def render_markdown(report: AnalysisReport) -> str:
    lines = [
        "# PathLens security report", "", "## Analysis scope", "",
        _text(report.scope), "",
        f"- Source: {_text(report.source)}", f"- Target: {_text(report.target)}",
        f"- Hop count: {report.hop_count}",
        f"- Relationships reported: {report.relationship_count}",
        "- Exploitability: not_assessed", "",
        "## Independently validated findings", "",
        "None produced. Independent validation was not performed; this does not establish absence of risk.", "",
        "## Selected node path", "",
    ]
    lines.extend(f"{index}. {_text(node)}" for index, node in enumerate(report.selected_path, 1))
    lines += ["", "## Graph evidence and provenance (input assertions)", ""]
    lines += _record(report.graph_metadata) if report.graph_metadata else ["Not supplied.", ""]
    lines += ["## Selected node assertions", ""]
    for node in report.nodes:
        lines += _record(node)
    lines += ["## Relationships by hop", ""]
    if not report.hops:
        lines += ["Source and target are the same node; no relationships traversed.", ""]
    for hop in report.hops:
        lines += [f"### Hop {hop.number}", "",
                  f"Source: {_text(hop.source)}; target: {_text(hop.target)}", ""]
        for index, relationship in enumerate(hop.relationships, 1):
            lines += [f"#### Relationship {index}", "",
                      "Graph assertion and supplied metadata:", ""]
            lines += _record(relationship.assertion)
            lines += [f"Description: {_text(relationship.description)}", "",
                      f"Semantics: {relationship.semantics_status.value}", "",
                      f"Target object-type compatibility: {relationship.target_compatibility.value}", "",
                      "Exploitability: not_assessed", ""]
            for title, values, empty in (
                ("Compatibility diagnostics", relationship.diagnostics, "No additional diagnostics; compatibility is not a verified access check."),
                ("Potential security implications (conditional)", relationship.potential_implications,
                 "None applied: semantics or target compatibility do not support an implication."),
                ("Prerequisites requiring validation", relationship.prerequisites, "Unknown; no supported guidance."),
                ("Limitations", relationship.limitations, "No additional limitations recorded."),
                ("Documentation references (not evidence)", relationship.references, "None available."),
            ):
                lines += [title + ":", ""]
                lines += [f"- {_text(value)}" for value in values] if values else [empty]
                lines += [""]
            lines += ["Defensive remediation:", "",
                      _text(relationship.remediation) if relationship.remediation else
                      "Unknown; no relationship-specific remediation is available.", ""]
    return "\n".join(lines).rstrip() + "\n"
