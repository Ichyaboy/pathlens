"""Synthetic assertions exercise semantics without treating them as access checks."""

import pytest

from pathlens.graph import GraphData, analyze_graph, build_graph, shortest_node_path
from pathlens.relationships import (
    Exploitability, RelationshipKind, SemanticsStatus, TargetCompatibility,
    lookup_relationship, target_compatibility,
)
from pathlens.semantics import lookup_relationship as legacy_lookup


LABELS = ["MemberOf", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AddMember"]


def graph_for(label: str, target_type: str):
    edge = {
        "source": "A", "target": "B", "relation": label,
        "evidence": {"claim": "exploitable", "validated": True},
        "provenance": {"fixture": "synthetic"},
    }
    graph = build_graph(GraphData.model_validate({
        "nodes": [{"id": "A", "type": "User"}, {"id": "B", "type": target_type}],
        "edges": [edge],
    }))
    return graph, edge


@pytest.mark.parametrize("label", LABELS)
def test_every_definition_has_required_metadata(label):
    definition = lookup_relationship(label)
    assert definition is legacy_lookup(label)
    assert definition.name == label
    assert definition.kind == RelationshipKind(label)
    assert definition.description.startswith("Input asserts")
    assert definition.applicable_target_types
    assert definition.potential_implications
    assert definition.prerequisites
    assert definition.limitations
    assert definition.remediation
    assert definition.references


@pytest.mark.parametrize("label", LABELS)
@pytest.mark.parametrize("target_type", [
    "Group", "User", "Computer", "OU", "Domain", "GPO", "Container",
    "CustomType", "group", "",
])
def test_target_compatibility_and_evidence_boundaries(label, target_type):
    known_type = target_type in {"Group", "User", "Computer", "OU", "Domain", "GPO", "Container"}
    expected = (
        TargetCompatibility.UNKNOWN if not known_type
        else TargetCompatibility.INCOMPATIBLE
        if label in {"MemberOf", "AddMember"} and target_type != "Group"
        else TargetCompatibility.COMPATIBLE
    )
    graph, edge = graph_for(label, target_type)
    result = analyze_graph(graph, "A", "B")
    report = result.relationships[0][0]
    assert report.semantics_status is SemanticsStatus.KNOWN
    assert report.target_compatibility is expected
    assert target_compatibility(report.semantics, target_type) is expected
    assert bool(report.warnings) == (expected is not TargetCompatibility.COMPATIBLE)
    assert bool(report.potential_implications) == (expected is TargetCompatibility.COMPATIBLE)
    assert report.edge.model_dump(exclude_unset=True) == edge
    assert result.exploitability is Exploitability.NOT_ASSESSED
    assert report.exploitability is Exploitability.NOT_ASSESSED
    assert [node.id for node in result.nodes] == ["A", "B"]


@pytest.mark.parametrize("label", ["FutureRelation", "writedacl", "WriteOwner ", "Owns"])
def test_unknown_relationship_semantics_preserve_evidence(label):
    graph, edge = graph_for(label, "Group")
    result = analyze_graph(graph, "A", "B")
    report = result.relationships[0][0]
    assert report.edge.model_dump(exclude_unset=True) == edge
    assert report.semantics_status is SemanticsStatus.UNKNOWN
    assert report.semantics is None
    assert report.target_compatibility is TargetCompatibility.UNKNOWN
    assert report.potential_implications == ()
    assert result.exploitability is Exploitability.NOT_ASSESSED


def test_traversal_does_not_consult_relationship_knowledge(monkeypatch):
    def fail_lookup(_label):
        raise AssertionError("Traversal consulted the relationship knowledge base")

    monkeypatch.setattr("pathlens.graph.lookup_relationship", fail_lookup)
    graph, _ = graph_for("WriteOwner", "CustomType")
    assert shortest_node_path(graph, "A", "B") == ["A", "B"]


def test_write_owner_is_not_unrestricted_ownership_transfer():
    definition = lookup_relationship("WriteOwner")
    assert any("arbitrary ownership transfer" in text for text in definition.limitations)
    assert any("OWNER RIGHTS" in text for text in definition.prerequisites)
    assert any("separate actions" in text for text in definition.limitations)


def test_write_dacl_is_not_a_completed_permission_change():
    definition = lookup_relationship("WriteDacl")
    assert any("not evidence that new rights were granted" in text for text in definition.limitations)
