"""Offline descriptions of supplied AD-style labels, not an access-check engine."""

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


class RelationshipKind(StrEnum):
    MEMBER_OF = "MemberOf"
    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    ADD_MEMBER = "AddMember"
    WRITE_DACL = "WriteDacl"
    WRITE_OWNER = "WriteOwner"


class RelationshipCategory(StrEnum):
    MEMBERSHIP = "membership"
    PERMISSION = "permission"


class TargetCompatibility(StrEnum):
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class Exploitability(StrEnum):
    NOT_ASSESSED = "not_assessed"


class SemanticsStatus(StrEnum):
    KNOWN = "known"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RelationshipSemantics:
    kind: RelationshipKind
    category: RelationshipCategory
    description: str
    prerequisites: tuple[str, ...]
    limitations: tuple[str, ...]
    remediation: str
    references: tuple[str, ...]
    required_target_type: str | None = None
    applicable_target_types: tuple[str, ...] = ()
    potential_implications: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.kind.value


_ACCESS = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584"
_GROUP = "https://learn.microsoft.com/en-us/windows/win32/ad/group-objects"
_OWNER_RIGHTS = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"
_OWNER_LIMITS = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c"
# Known custom-schema labels for directory objects, not an exhaustive AD schema.
_DIRECTORY_TYPES = ("User", "Group", "Computer", "OU", "Domain", "GPO", "Container")
_PERMISSION_CHECKS = (
    "Validate effective rights for the source security principal, including applicable allow/deny ACEs and inheritance.",
    "Validate target object class, attribute restrictions, and current directory state.",
)
_PERMISSION_LIMITS = (
    "A supplied permission label is not a verified access check or a completed action.",
    "Adjacent graph relationships do not establish an executable attack chain.",
)

RELATIONSHIPS: Mapping[RelationshipKind, RelationshipSemantics] = MappingProxyType({
    RelationshipKind.MEMBER_OF: RelationshipSemantics(
        RelationshipKind.MEMBER_OF, RelationshipCategory.MEMBERSHIP,
        "Input asserts membership of the source in the target group.",
        ("Validate membership, group category and scope, and the applicable security token.",),
        ("Membership alone does not establish the group's effective privileges or control of its members.",),
        "Review membership and remove unnecessary assignments after checking business needs.",
        (_GROUP,), "Group",
        applicable_target_types=("Group",),
        potential_implications=(
            "Security-group membership may contribute the group's granted rights to an applicable token.",
        ),
    ),
    RelationshipKind.GENERIC_ALL: RelationshipSemantics(
        RelationshipKind.GENERIC_ALL, RelationshipCategory.PERMISSION,
        "Input asserts GenericAll rights over the target directory object.",
        _PERMISSION_CHECKS, _PERMISSION_LIMITS,
        "Review broad object control and replace unnecessary grants with scoped delegation.",
        (_ACCESS,),
        applicable_target_types=_DIRECTORY_TYPES,
        potential_implications=(
            "Effective broad rights may permit changes to the object's attributes and permissions.",
        ),
    ),
    RelationshipKind.GENERIC_WRITE: RelationshipSemantics(
        RelationshipKind.GENERIC_WRITE, RelationshipCategory.PERMISSION,
        "Input asserts GenericWrite rights over the target directory object.",
        _PERMISSION_CHECKS,
        _PERMISSION_LIMITS + ("GenericWrite does not itself grant permission to rewrite the DACL or take ownership.",),
        "Review write delegation and restrict unnecessary grants to required attributes.",
        (_ACCESS,),
        applicable_target_types=_DIRECTORY_TYPES,
        potential_implications=(
            "Writable attributes may affect security-sensitive configuration, depending on the object class.",
        ),
    ),
    RelationshipKind.ADD_MEMBER: RelationshipSemantics(
        RelationshipKind.ADD_MEMBER, RelationshipCategory.PERMISSION,
        "Input asserts permission to modify the target group's member attribute.",
        _PERMISSION_CHECKS + ("Verify write access to the member attribute; self-membership rights alone are not equivalent.",),
        _PERMISSION_LIMITS + ("AddMember is this schema's label, not proof that any membership was changed.",),
        "Review delegation on the member attribute and remove unnecessary membership-management rights.",
        (_ACCESS, _GROUP), "Group",
        applicable_target_types=("Group",),
        potential_implications=(
            "A permitted membership change may give a member rights granted to a security group.",
        ),
    ),
    RelationshipKind.WRITE_DACL: RelationshipSemantics(
        RelationshipKind.WRITE_DACL, RelationshipCategory.PERMISSION,
        "Input asserts permission to change the target object's discretionary access-control list (DACL).",
        _PERMISSION_CHECKS + (
            "Verify effective WRITE_DAC access and the scope of the affected security descriptor.",
        ),
        _PERMISSION_LIMITS + (
            "Permission to change a DACL is not evidence that new rights were granted or used.",
        ),
        "Remove unnecessary DACL-write delegation; review inherited grants and audit permission changes.",
        (_ACCESS,),
        applicable_target_types=_DIRECTORY_TYPES,
        potential_implications=(
            "Changing the DACL may allow additional permissions to be granted on the target object.",
        ),
    ),
    RelationshipKind.WRITE_OWNER: RelationshipSemantics(
        RelationshipKind.WRITE_OWNER, RelationshipCategory.PERMISSION,
        "Input asserts permission to change the owner in the target object's security descriptor.",
        _PERMISSION_CHECKS + (
            "Verify effective WRITE_OWNER access and which owner SID the caller is allowed to assign.",
            "Check OWNER RIGHTS ACEs before inferring an owner's ability to change the DACL.",
            "Check directory policy and server-version restrictions on implicit owner rights.",
        ),
        _PERMISSION_LIMITS + (
            "WRITE_OWNER alone does not authorize arbitrary ownership transfer to another principal.",
            "Ownership changes and subsequent permission changes are separate actions, neither established by this label.",
        ),
        "Remove unnecessary ownership-write delegation; review object owners and audit ownership changes.",
        (_ACCESS, _OWNER_RIGHTS, _OWNER_LIMITS),
        applicable_target_types=_DIRECTORY_TYPES,
        potential_implications=(
            "Taking ownership may enable subsequent DACL changes, subject to owner-rights restrictions.",
        ),
    ),
})


def lookup_relationship(relation: str) -> RelationshipSemantics | None:
    """Exact, case-sensitive lookup; never normalize or replace raw labels."""
    try:
        kind = RelationshipKind(relation)
    except ValueError:
        return None
    return RELATIONSHIPS[kind]


def endpoint_warnings(
    semantics: RelationshipSemantics | None, target_type: str,
) -> tuple[str, ...]:
    if semantics is not None and semantics.required_target_type is not None:
        if target_type != semantics.required_target_type:
            return (
                f"{semantics.kind.value} expects target type Group; supplied type {target_type!r}. "
                "The membership interpretation is not supported for this endpoint.",
            )
    if semantics is not None and target_compatibility(semantics, target_type) is TargetCompatibility.UNKNOWN:
        return (
            f"{semantics.name}: target type {target_type!r} has unknown compatibility; "
            "validate the directory object class before applying this interpretation.",
        )
    return ()


def target_compatibility(
    semantics: RelationshipSemantics | None, target_type: str,
) -> TargetCompatibility:
    """Class-label compatibility only; never an access check or evidence validation."""
    if semantics is None:
        return TargetCompatibility.UNKNOWN
    if target_type in semantics.applicable_target_types:
        return TargetCompatibility.COMPATIBLE
    if semantics.required_target_type and target_type in _DIRECTORY_TYPES:
        return TargetCompatibility.INCOMPATIBLE
    return TargetCompatibility.UNKNOWN
