"""Inconclusive items a contract's budget accepts by name, each with its reason.

``budget.accepted_inconclusive`` (approved 2026-11-27) names the items that may stay
``inconclusive`` and says why. Once a contract names any, an inconclusive finding it
does not name is over budget whatever the count, and ``max_inconclusive`` still caps
the total. A contract that names none keeps the count-only rule.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from pydantic import Field, field_validator

from fns.models.base import FnsModel


class AcceptedInconclusive(FnsModel):
    """One contract item the budget lets stay inconclusive."""

    target: str = Field(
        pattern=r"^(?:resource|directory|application|service_principal):\S+$", max_length=300
    )
    """The item's target as findings name it, e.g. ``directory:tenant``."""
    operation: str = Field(pattern=r"^\S+$", max_length=200)
    reason: str = Field(pattern=r"\S", max_length=500)
    """Why this item may stay inconclusive. Required: an accepted gap is explained."""

    @field_validator("target")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()

    @property
    def item(self) -> str:
        return f"{self.target} {self.operation}"


def sorted_accepted(
    v: tuple[AcceptedInconclusive, ...],
) -> tuple[AcceptedInconclusive, ...]:
    items = [a.item for a in v]
    if len(set(items)) != len(items):
        raise ValueError("each accepted_inconclusive item must be listed once")
    return tuple(sorted(v, key=lambda a: a.item))


def unaccepted_inconclusive(
    inconclusive: Iterable[tuple[str, str]], accepted: Sequence[AcceptedInconclusive]
) -> tuple[str, ...]:
    """The inconclusive ``(target, operation)`` items the budget does not name, as
    ``"<target> <operation>"``, sorted. Always empty while the budget names none."""
    if not accepted:
        return ()
    named = {(a.target, a.operation) for a in accepted}
    return tuple(sorted({f"{t} {o}" for t, o in inconclusive if (t.lower(), o) not in named}))
