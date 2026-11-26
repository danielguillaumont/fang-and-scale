"""Resolve contract references against a snapshot.

Short names match ``display_name`` case-insensitively among entities of a
compatible type. Zero or several matches is an error the evaluator turns into
``inconclusive``; it never guesses.
"""

from __future__ import annotations

from dataclasses import dataclass

from fns.models.armid import ArmIdError, normalize_arm_id
from fns.models.snapshot import Entity, Snapshot

PRINCIPAL_TYPES = frozenset({"servicePrincipal", "managedIdentity"})


@dataclass(frozen=True, slots=True)
class Resolved:
    entity: Entity | None
    reason: str
    """Why it resolved (or did not), for the finding's reasons."""


def _by_name(snapshot: Snapshot, name: str, types: frozenset[str]) -> list[Entity]:
    wanted = name.lower()
    return [
        e
        for e in snapshot.entities
        if e.type in types and e.display_name is not None and e.display_name.lower() == wanted
    ]


def _one(matches: list[Entity], what: str) -> Resolved:
    if len(matches) == 1:
        e = matches[0]
        return Resolved(e, f"{what} resolved to {e.id}")
    if not matches:
        return Resolved(None, f"{what} is not in the snapshot")
    ids = ", ".join(sorted(e.id for e in matches)[:3])
    return Resolved(None, f"{what} is ambiguous ({len(matches)} matches: {ids})")


def resolve_identity(snapshot: Snapshot, ref: str) -> Resolved:
    """``sp:<name|appId>``, ``mi:<name>`` or ``objectId:<guid>``."""
    kind, _, value = ref.partition(":")
    what = f"identity {ref}"
    if kind == "objectId":
        oid = value.lower()
        return _one(
            [e for e in snapshot.entities if e.id == oid and e.type in PRINCIPAL_TYPES], what
        )
    if kind == "mi":
        return _one(_by_name(snapshot, value, frozenset({"managedIdentity"})), what)
    by_app_id = [
        e
        for e in snapshot.entities
        if e.type == "servicePrincipal"
        and str(e.properties.get("appId", "")).lower() == value.lower()
    ]
    return _one(by_app_id or _by_name(snapshot, value, frozenset({"servicePrincipal"})), what)


def resolve_resource(snapshot: Snapshot, ref: str) -> Resolved:
    what = f"resource {ref}"
    if ref.startswith("/"):
        try:
            rid = normalize_arm_id(ref)
        except ArmIdError as exc:
            return Resolved(None, f"{what} is not a valid ARM ID: {exc}")
        return _one([e for e in snapshot.entities if e.id == rid and e.type == "resource"], what)
    return _one(_by_name(snapshot, ref, frozenset({"resource"})), what)
