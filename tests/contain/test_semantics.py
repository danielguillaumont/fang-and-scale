"""One test per semantics-table way: granting exactly that thing reaches the
operation, and granting nothing does not."""

from __future__ import annotations

from typing import Any

import pytest

from fns.contain import semantics as sem
from fns.contain.evaluate import evaluate
from tests.contain.helpers import KV, RG, ST, Snap, contract
from tests.factories import pid

AGENT = pid(100)
CUSTOM = f"{RG}/providers/Microsoft.Authorization/roleDefinitions/{pid(4242)}"

WAYS = [
    pytest.param(s, w, id=f"{s.target}:{s.operation}:{w.rule}:{w.kind}")
    for s in sem.TABLE.values()
    for w in s.ways
]


def _world(s: sem.OperationSemantics, way: sem.Way | None) -> tuple[Snap, dict[str, Any]]:
    snap = Snap()
    snap.sp(100, "sp-agent")
    if s.target == "directory":
        item: dict[str, Any] = {"directory": "tenant", "operations": [s.operation]}
    else:
        rtype = way.resource_types[0] if way and way.resource_types else sem.KEY_VAULT
        rid = KV if rtype == sem.KEY_VAULT else ST
        snap.resource(
            rid, "Microsoft.KeyVault/vaults" if rid == KV else "Microsoft.Storage/storageAccounts"
        )
        item = {"resource": rid, "operations": [s.operation]}
    if way is None:
        return snap, item
    if way.kind in {"action", "dataAction"}:
        key = "actions" if way.kind == "action" else "dataActions"
        snap.entity(CUSTOM, "roleDefinition", "custom", **{key: (way.values[0],)})
        snap.edge(
            "hasRbacRole",
            AGENT,
            RG.lower(),
            role_definition_id=CUSTOM,
            assignment_id=f"{RG}/providers/Microsoft.Authorization/roleAssignments/{pid(4243)}",
        )
    elif way.kind == "appPerm":
        snap.graph_perm(AGENT, way.values[0])
    elif way.kind == "dirRole":
        snap.dir_role(AGENT, way.values[0])
    elif way.kind == "ownedObjectPerm":
        snap.app(102, "owned-app")
        snap.edge("owns", AGENT, pid(102)).graph_perm(AGENT, way.values[0])
    return snap, item


@pytest.mark.parametrize(("s", "way"), WAYS)
def test_each_way_reaches_its_operation(s: sem.OperationSemantics, way: sem.Way) -> None:
    snap, item = _world(s, way)
    (o,) = evaluate(contract([item], who="sp:sp-agent"), snap.build()).outcomes
    assert o.finding.verdict == "fail", o.finding.reasons
    assert o.paths[0].steps[-1].rule == way.rule


@pytest.mark.parametrize("s", list(sem.TABLE.values()), ids=lambda s: f"{s.target}:{s.operation}")
def test_without_a_grant_nothing_is_reached(s: sem.OperationSemantics) -> None:
    snap, item = _world(s, None)
    (o,) = evaluate(contract([item], who="sp:sp-agent"), snap.build()).outcomes
    assert o.finding.verdict == "inconclusive"


def test_table_keys_are_unique_and_versioned() -> None:
    assert sem.SEMANTICS_VERSION == 1
    assert len(sem.TABLE) == 10
    assert sem.lookup("resource", "SECRETS/GET") is sem.lookup("resource", "secrets/get")
    assert sem.lookup("resource", "certificates/get") is None


def test_graph_permissions_in_use_cover_every_rule() -> None:
    assert {
        sem.APP_READWRITE_ALL,
        sem.APP_READWRITE_OWNEDBY,
        sem.APPROLE_READWRITE_ALL,
        sem.ROLEMANAGEMENT_READWRITE,
    } <= sem.graph_permissions_in_use()
