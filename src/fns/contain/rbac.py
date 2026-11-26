"""Azure RBAC evaluation over snapshot facts.

- Action patterns are case-insensitive globs where ``*`` matches any run of
  characters (Azure's wildcard semantics for ``actions`` and ``dataActions``).
- A role grants an action when an ``actions`` (or ``dataActions``) pattern
  matches and no ``notActions`` (``notDataActions``) pattern does. Control-plane
  and data-plane lists never mix: Contributor's ``*`` grants no data action.
- Scope relations compare whole ``/``-separated segments of normalized IDs,
  never string prefixes, so ``rg-lab`` is not an ancestor of ``rg-lab-prod``.
- Deny assignments subtract, honouring excluded principals and
  ``doNotApplyToChildScopes``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import Final, Literal

from fns.models.snapshot import EVERYONE_PRINCIPAL_ID, TENANT_ROOT_SCOPE, DenyAssignment, Entity

ANY_ROLE: Final = "*"
"""Synthetic role definition ID: every action and data action (``rbac-write``)."""

_MG_PREFIX: Final = "/providers/microsoft.management/managementgroups/"

ScopeRelation = Literal["self", "ancestor", "descendant"]


@lru_cache(maxsize=4096)
def _pattern(pattern: str) -> re.Pattern[str]:
    parts = (re.escape(p) for p in pattern.split("*"))
    return re.compile(".*".join(parts), re.IGNORECASE)


def action_matches(pattern: str, action: str) -> bool:
    return _pattern(pattern).fullmatch(action) is not None


def grants(allowed: Iterable[str], excluded: Iterable[str], action: str) -> bool:
    return any(action_matches(p, action) for p in allowed) and not any(
        action_matches(p, action) for p in excluded
    )


@dataclass(frozen=True, slots=True)
class RoleDefinition:
    id: str
    name: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    data_actions: tuple[str, ...]
    not_data_actions: tuple[str, ...]

    @classmethod
    def from_entity(cls, entity: Entity) -> RoleDefinition:
        def tup(key: str) -> tuple[str, ...]:
            value = entity.properties.get(key)
            return value if isinstance(value, tuple) else ()

        return cls(
            entity.id,
            entity.display_name or entity.id,
            tup("actions"),
            tup("notActions"),
            tup("dataActions"),
            tup("notDataActions"),
        )

    def permits(self, action: str, *, data: bool) -> bool:
        if self.id == ANY_ROLE:
            return True
        if data:
            return grants(self.data_actions, self.not_data_actions, action)
        return grants(self.actions, self.not_actions, action)


ANY = RoleDefinition(ANY_ROLE, "any role (rbac-write)", ("*",), (), ("*",), ())


def _segments(scope_id: str) -> list[str]:
    return scope_id.lower().strip("/").split("/")


def scope_relation(scope: str, target: str) -> ScopeRelation | None:
    """How an assignment ``scope`` relates to ``target`` (both normalized ARM IDs).

    The root scope ``/`` and management groups are treated as ancestors of every
    subscription-level target: ARM lists only assignments that apply to the
    subscription it was asked about, so an inherited one is in effect here.
    """
    scope, target = scope.lower(), target.lower()
    if scope == target:
        return "self"
    if scope == TENANT_ROOT_SCOPE:
        return "ancestor"
    if scope.startswith(_MG_PREFIX):
        return "ancestor" if target.startswith("/subscriptions/") else None
    s, t = _segments(scope), _segments(target)
    if len(s) < len(t) and t[: len(s)] == s:
        return "ancestor"
    if len(t) < len(s) and s[: len(t)] == t:
        return "descendant"
    return None


def deny_applies(
    deny: DenyAssignment,
    principals: frozenset[str],
    action: str,
    *,
    data: bool,
    at_scope: str,
) -> bool:
    """Does ``deny`` block ``action`` for a caller whose effective principal set is
    ``principals`` (the identity plus its groups) at ``at_scope``?"""
    if deny.src != EVERYONE_PRINCIPAL_ID and deny.src not in principals:
        return False
    if principals & {str(p) for p in deny.excluded_principal_ids}:
        return False
    rel = scope_relation(deny.dst, at_scope)
    if rel is None or rel == "descendant":
        return False
    if rel == "ancestor" and deny.do_not_apply_to_child_scopes:
        return False
    if data:
        return grants(deny.data_actions, deny.not_data_actions, action)
    return grants(deny.actions, deny.not_actions, action)
