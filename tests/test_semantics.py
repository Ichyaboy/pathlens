from dataclasses import FrozenInstanceError

import pytest

from pathlens.graph import GraphData, analyze_graph, build_graph
from pathlens.semantics import (
    RELATIONSHIPS, RelationshipCategory, RelationshipKind, lookup_relationship,
)


@pytest.mark.parametrize("kind", list(RelationshipKind))
def test_typed_definitions_have_bounded_guidance(kind):
    definition = lookup_relationship(kind.value)
    assert definition.kind is kind
    assert definition.category is (
        RelationshipCategory.MEMBERSHIP if kind is RelationshipKind.MEMBER_OF
        else RelationshipCategory.PERMISSION
    )
    assert definition.prerequisites and definition.limitations
    assert definition.remediation and definition.references
    with pytest.raises(FrozenInstanceError):
        definition.description = "changed"
    with pytest.raises(TypeError):
        RELATIONSHIPS[kind] = definition


@pytest.mark.parametrize("label", ["memberof", "MemberOf ", "", "Owns", "[bold]MemberOf[/bold]"])
def test_unknown_names_are_not_coerced(label):
    assert lookup_relationship(label) is None


@pytest.mark.parametrize("relation", ["MemberOf", "AddMember"])
@pytest.mark.parametrize("target_type", ["Group", "User", "group", "CustomType"])
def test_membership_endpoint_warning_preserves_assertion(relation, target_type):
    edge = {"source": "A", "target": "B", "relation": relation,
            "evidence": None, "provenance": {"collector": ["synthetic"]}}
    raw = {
        "nodes": [{"id": "A", "type": "User"}, {"id": "B", "type": target_type}],
        "edges": [edge, edge],
    }
    graph = build_graph(GraphData.model_validate(raw))
    result = analyze_graph(graph, "A", "B")
    assert [n.id for n in result.nodes] == ["A", "B"]
    assert len(result.relationships[0]) == 2
    for report in result.relationships[0]:
        assert report.recognized
        assert report.semantics.kind.value == relation
        assert bool(report.warnings) == (target_type != "Group")
        assert report.edge.model_dump(exclude_unset=True) == edge
    result.relationships[0][0].edge.provenance["collector"].append("changed")
    assert result.relationships[0][1].edge.provenance == edge["provenance"]
    assert graph["A"]["B"][0]["provenance"] == edge["provenance"]


def test_generic_write_does_not_claim_dacl_or_ownership_rights():
    definition = lookup_relationship("GenericWrite")
    assert "GenericWrite does not itself grant permission to rewrite the DACL or take ownership." in definition.limitations


def test_unknown_report_has_no_semantics_or_invented_provenance():
    graph = build_graph(GraphData.model_validate({
        "nodes": [{"id": "A", "type": "Custom"}, {"id": "B", "type": "Custom"}],
        "edges": [{"source": "A", "target": "B", "relation": "FutureRelation"}],
    }))
    report = analyze_graph(graph, "A", "B").relationships[0][0]
    assert not report.recognized
    assert report.semantics is None
    assert report.warnings == ()
    assert "provenance" not in report.edge.model_dump(exclude_unset=True)
