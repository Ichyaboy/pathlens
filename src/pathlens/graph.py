"""Directed multigraph analysis; graph paths do not establish exploitability."""

from collections import deque
from copy import deepcopy
from dataclasses import dataclass
import json

import networkx as nx
from pydantic import BaseModel, ConfigDict, JsonValue, model_validator

from pathlens.relationships import (
    Exploitability, RelationshipSemantics, SemanticsStatus, TargetCompatibility,
    endpoint_warnings, lookup_relationship, target_compatibility,
)


class MetadataModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, strict=True, hide_input_in_errors=True)

    evidence: JsonValue = None
    provenance: JsonValue = None


class Node(MetadataModel):
    id: str
    type: str


class Edge(MetadataModel):
    source: str
    target: str
    relation: str


class GraphData(MetadataModel):
    nodes: list[Node]
    edges: list[Edge]

    @model_validator(mode="after")
    def check_references(self) -> "GraphData":
        ids = {node.id for node in self.nodes}
        if len(ids) != len(self.nodes):
            raise ValueError("Duplicate node IDs")
        for edge in self.edges:
            if edge.source not in ids or edge.target not in ids:
                raise ValueError("Unknown node referenced by edge")
        return self


def build_graph(data: GraphData) -> nx.MultiDiGraph:
    """Preserve all supplied metadata, including absent versus explicit null."""
    graph = nx.MultiDiGraph()
    graph.graph.update(deepcopy(data.model_dump(
        exclude={"nodes", "edges"}, exclude_unset=True,
    )))
    for node in data.nodes:
        graph.add_node(node.id, **deepcopy(node.model_dump(exclude_unset=True)))
    for edge in data.edges:
        graph.add_edge(
            edge.source, edge.target,
            **deepcopy(edge.model_dump(exclude_unset=True)),
        )
    return graph


def shortest_node_path(
    graph: nx.MultiDiGraph, source: str, target: str,
) -> list[str]:
    """Minimize hops, then the node-ID sequence using case-sensitive Unicode order."""
    if source not in graph or target not in graph:
        raise nx.NodeNotFound("Unknown source or target.")
    parents: dict[str, str | None] = {source: None}
    pending = deque([source])
    while pending:
        node = pending.popleft()
        if node == target:
            path: list[str] = []
            current: str | None = target
            while current is not None:
                path.append(current)
                current = parents[current]
            return path[::-1]
        for successor in sorted(graph.successors(node)):
            if successor not in parents:
                parents[successor] = node
                pending.append(successor)
    raise nx.NetworkXNoPath(f"No directed path from {source!r} to {target!r}.")


@dataclass
class RelationshipReport:
    """The original edge is an input assertion, not a verified directory fact."""
    edge: Edge
    recognized: bool
    explanation: str
    semantics: RelationshipSemantics | None = None
    warnings: tuple[str, ...] = ()
    target_compatibility: TargetCompatibility = TargetCompatibility.UNKNOWN

    @property
    def semantics_status(self) -> SemanticsStatus:
        return SemanticsStatus.KNOWN if self.semantics else SemanticsStatus.UNKNOWN

    @property
    def exploitability(self) -> Exploitability:
        return Exploitability.NOT_ASSESSED

    @property
    def potential_implications(self) -> tuple[str, ...]:
        # Do not apply class-specific implications to incompatible/unknown targets.
        if self.semantics and self.target_compatibility is TargetCompatibility.COMPATIBLE:
            return self.semantics.potential_implications
        return ()


@dataclass
class PathAnalysis:
    nodes: list[Node]
    relationships: list[list[RelationshipReport]]
    metadata: dict[str, JsonValue]

    @property
    def exploitability(self) -> Exploitability:
        return Exploitability.NOT_ASSESSED


def report_relationships(
    graph: nx.MultiDiGraph, source: str, target: str,
) -> list[RelationshipReport]:
    """Report every parallel edge, sorted by relation then canonical JSON."""
    edges = sorted(
        graph[source][target].values(),
        key=lambda attrs: (
            attrs["relation"],
            json.dumps(attrs, sort_keys=True, ensure_ascii=True, allow_nan=False),
        ),
    )
    reports = []
    for attrs in edges:
        semantics = lookup_relationship(attrs["relation"])
        reports.append(RelationshipReport(
            edge=Edge.model_validate(deepcopy(attrs)),
            recognized=semantics is not None,
            explanation=(semantics.description if semantics else
                         "Unrecognized relationship; no security conclusion available."),
            semantics=semantics,
            warnings=endpoint_warnings(semantics, graph.nodes[target]["type"]),
            target_compatibility=target_compatibility(semantics, graph.nodes[target]["type"]),
        ))
    return reports


def analyze_graph(
    graph: nx.MultiDiGraph, source: str, target: str,
) -> PathAnalysis:
    path = shortest_node_path(graph, source, target)
    return PathAnalysis(
        nodes=[Node.model_validate(deepcopy(graph.nodes[node])) for node in path],
        relationships=[
            report_relationships(graph, start, end)
            for start, end in zip(path, path[1:])
        ],
        metadata=deepcopy(graph.graph),
    )
