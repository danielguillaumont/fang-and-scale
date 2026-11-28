"""Transitive group memberships (queue item 3, pending review)."""

from __future__ import annotations

from typing import Any

from fns.adapters.azure import graph
from fns.adapters.azure.http import ApiRequest, ApiResponse
from fns.fixtures.replay import FixtureTransport
from fns.inventory.collector import (
    MEMBERSHIPS,
    MEMBERSHIPS_LEFT,
    NOT_COLLECTED,
    TRANSITIVE_COLLECTOR,
)
from fns.models.snapshot import GROUP_ROLE_ASSIGNABLE
from tests.factories import pid
from tests.inventory.test_collector import FIXTURE, GOLDEN, _manifest, run

AGENT = pid(100)
NESTED, ROLE_GROUP, UNKNOWN = pid(980), pid(981), pid(982)


class WithGroups:
    def __init__(
        self, rows: dict[str, list[Any]] | None = None, status: dict[str, int] | None = None
    ) -> None:
        self.inner = FixtureTransport(FIXTURE)
        self.rows = rows or {}
        self.status = status or {}
        self.requests: list[ApiRequest] = []

    def fetch(self, request: ApiRequest) -> ApiResponse:
        self.requests.append(request)
        if request.operation == graph.OP_SP_TRANSITIVE_GROUPS:
            sp = request.url.split("/servicePrincipals/")[1].split("/")[0]
            if sp in self.status:
                return ApiResponse(self.status[sp], {"error": {"code": "Forbidden"}}, "rid")
            return ApiResponse(200, {"value": self.rows.get(sp, [])}, "rid")
        return self.inner.fetch(request)

    def unused(self) -> list[str]:
        return self.inner.unused()


def _scope() -> Any:
    m = _manifest()
    scout = sorted({*m.allowed_operations["scout"], graph.OP_SP_TRANSITIVE_GROUPS})
    return _manifest(allowed_operations={**m.allowed_operations, "scout": scout})


def _reason(snap: Any) -> list[str]:
    return [n.reason for n in snap.coverage.not_collected if n.surface == MEMBERSHIPS]


def test_a_scope_without_the_read_is_unchanged() -> None:
    r = run()
    assert r.snapshot.digest() == GOLDEN
    (default,) = [n for n in NOT_COLLECTED if n.surface == MEMBERSHIPS]
    assert _reason(r.snapshot) == [default.reason]
    assert graph.OP_SP_TRANSITIVE_GROUPS not in {d.operation for d in r.journal.decisions}


def test_nested_groups_and_role_assignability_are_collected() -> None:
    rows = {
        AGENT: [
            {"id": NESTED, "displayName": "grp-nested", "isAssignableToRole": False},
            {"id": ROLE_GROUP, "displayName": "grp-roles", "isAssignableToRole": True},
            {"id": UNKNOWN, "displayName": "grp-unknown", "isAssignableToRole": None},
        ]
    }
    t = WithGroups(rows)
    r = run(t, _scope())
    snap = r.snapshot
    member = {e.dst for e in snap.edges if e.type == "memberOf" and e.src == AGENT}
    assert {NESTED, ROLE_GROUP, UNKNOWN} <= member
    props = {e.id: e.properties.get(GROUP_ROLE_ASSIGNABLE) for e in snap.entities}
    assert props[NESTED] is False and props[ROLE_GROUP] is True
    assert props[UNKNOWN] is None  # not stated: unknown, never false
    assert r.collector(TRANSITIVE_COLLECTOR).status == "complete"
    (reason,) = _reason(snap)
    assert reason.startswith("transitive group memberships of in-scope service principals")
    assert reason.endswith(MEMBERSHIPS_LEFT)
    asked = [q for q in t.requests if q.operation == graph.OP_SP_TRANSITIVE_GROUPS]
    assert asked and all(
        q.url.endswith("?$select=id,displayName,isAssignableToRole") for q in asked
    )
    assert all("/transitiveMemberOf/microsoft.graph.group?" in q.url for q in asked)


def test_a_failed_listing_keeps_the_reason() -> None:
    r = run(WithGroups(status={AGENT: 403}), _scope())
    assert r.collector(TRANSITIVE_COLLECTOR).status == "partial"
    (reason,) = _reason(r.snapshot)
    assert reason.startswith(f"collector {TRANSITIVE_COLLECTOR} is partial; ")


def test_a_bad_row_is_counted() -> None:
    r = run(WithGroups({AGENT: [{"id": "x"}, {"displayName": "no id"}]}), _scope())
    assert "bad-item" in r.collector(TRANSITIVE_COLLECTOR).error_codes


def test_order_does_not_change_the_digest() -> None:
    rows = [{"id": NESTED, "displayName": "a"}, {"id": ROLE_GROUP, "displayName": "b"}]
    a = run(WithGroups({AGENT: rows}), _scope()).snapshot
    b = run(WithGroups({AGENT: rows[::-1]}), _scope()).snapshot
    assert a.digest() == b.digest()
