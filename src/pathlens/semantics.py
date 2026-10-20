"""Compatibility imports; relationship definitions live in pathlens.relationships."""

from pathlens.relationships import (
    RELATIONSHIPS,
    RelationshipCategory,
    RelationshipKind,
    RelationshipSemantics,
    endpoint_warnings,
    lookup_relationship,
)

__all__ = [
    "RELATIONSHIPS", "RelationshipCategory", "RelationshipKind",
    "RelationshipSemantics", "endpoint_warnings", "lookup_relationship",
]
