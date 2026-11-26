from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fns.adapters.azure import arm, graph
from fns.fixtures import wellknown as wk
from fns.inventory.builder import PRIORITY_PRIMARY, PRIORITY_STUB, SnapshotBuilder
from fns.models.snapshot import EntityType, Provenance, SnapshotCoverage
from tests.factories import KV, RG, SUB, TENANT, pid

PROV = Provenance(source_api="test", observed_at=datetime(2026, 11, 25, tzinfo=UTC))
SUBID = f"/subscriptions/{SUB}"
MG = "/providers/Microsoft.Management/managementGroups/mg-root"


def _ra(
    scope: str, role_def: str, principal: str = pid(100), ptype: str = "ServicePrincipal"
) -> dict[str, Any]:
    return {
        "id": f"{scope.rstrip('/')}/providers/Microsoft.Authorization/roleAssignments/{pid(400)}",
        "properties": {
            "roleDefinitionId": role_def,
            "principalId": principal,
            "principalType": ptype,
            "scope": scope,
        },
    }


def _build(b: SnapshotBuilder) -> Any:
    return b.build(
        mode="FIXTURE",
        tenant_id=TENANT,
        collected_at=PROV.observed_at,
        collector_version="t",
        coverage=SnapshotCoverage(collectors=(), not_collected=()),
    )


# --- ARM ----------------------------------------------------------------------------


def test_root_scope_assignment_is_kept() -> None:
    b = SnapshotBuilder()
    refs, errors = arm.parse_role_assignments(
        b,
        [
            _ra(
                "/",
                f"{SUBID}/providers/Microsoft.Authorization/roleDefinitions/{wk.USER_ACCESS_ADMINISTRATOR}",
            )
        ],
        PROV,
    )
    assert errors == []
    snap = _build(b)
    (edge,) = snap.edges
    assert edge.dst == "/"
    assert {e.id for e in snap.entities if e.type == "scope"} == {"/"}
    assert len(refs) == 1


def test_mg_scoped_definition_is_fetched_through_the_subscription() -> None:
    rd = f"{MG}/providers/Microsoft.Authorization/roleDefinitions/{pid(500)}"
    req = arm.role_definition_request(SUB, arm.role_definition_guid(rd))
    assert req.url.startswith(f"https://management.azure.com{SUBID}/providers/")
    assert pid(500) in req.url
    b = SnapshotBuilder()
    body = {
        "id": f"{SUBID}/providers/Microsoft.Authorization/roleDefinitions/{pid(500)}",
        "properties": {
            "roleName": "custom",
            "type": "CustomRole",
            "permissions": [{"actions": ["b", "a"]}],
        },
    }
    arm.parse_role_definition(b, body, rd)
    (ent,) = _build(b).entities
    assert ent.id == rd.lower()  # registered under the ID the assignment references
    assert ent.properties["actions"] == ("a", "b")


def test_role_definition_response_must_match_request() -> None:
    body = {
        "id": f"{SUBID}/providers/Microsoft.Authorization/roleDefinitions/{wk.OWNER}",
        "properties": {"permissions": []},
    }
    with pytest.raises(arm.ParseError):
        arm.parse_role_definition(
            SnapshotBuilder(),
            body,
            f"{SUBID}/providers/Microsoft.Authorization/roleDefinitions/{wk.READER}",
        )


def test_unknown_principal_type_is_reported_not_guessed() -> None:
    b = SnapshotBuilder()
    rd = f"{SUBID}/providers/Microsoft.Authorization/roleDefinitions/{wk.READER}"
    _, errors = arm.parse_role_assignments(b, [_ra(SUBID, rd, ptype="Device")], PROV)
    assert errors == ["unknown-principal-type"]
    assert _build(b).edges == ()


def test_malformed_assignment_is_counted() -> None:
    _, errors = arm.parse_role_assignments(
        SnapshotBuilder(), [{"id": "x"}, {"properties": {}}], PROV
    )
    assert errors == ["bad-item", "bad-item"]


def test_user_assigned_identities_become_has_identity_edges() -> None:
    b = SnapshotBuilder()
    item = {
        "id": KV,
        "name": "kv",
        "type": "Microsoft.KeyVault/vaults",
        "identity": {
            "principalId": pid(600),
            "userAssignedIdentities": {"/x/ua": {"principalId": pid(601)}},
        },
    }
    assert arm.parse_resources(b, RG, [item], PROV) == []
    snap = _build(b)
    assert {e.dst for e in snap.edges if e.type == "hasIdentity"} == {pid(600), pid(601)}


def test_everyone_deny_assignment_creates_synthetic_principal() -> None:
    b = SnapshotBuilder()
    item = {
        "id": f"{KV}/providers/Microsoft.Authorization/denyAssignments/{pid(410)}",
        "properties": {
            "scope": KV,
            "permissions": [{"actions": ["x/y/action"]}],
            "principals": [{"id": wk.EVERYONE, "type": "SystemDefined"}],
        },
    }
    assert arm.parse_deny_assignments(b, [item], PROV) == []
    snap = _build(b)
    everyone = next(e for e in snap.entities if e.id == wk.EVERYONE)
    assert everyone.properties["synthetic"] is True


# --- Graph --------------------------------------------------------------------------


def test_app_role_value_is_resolved_from_resource_service_principal() -> None:
    b = SnapshotBuilder()
    roles, _ = graph.parse_service_principals(
        b,
        [
            {
                "id": pid(103),
                "appId": wk.MICROSOFT_GRAPH_APP_ID,
                "displayName": "Microsoft Graph",
                "appRoles": [{"id": wk.DIRECTORY_READ_ALL, "value": "Directory.Read.All"}],
            },
            {"id": pid(100), "appId": pid(200), "displayName": "agent"},
        ],
    )
    items = [
        {
            "id": "opaque-1",
            "principalId": pid(100),
            "resourceId": pid(103),
            "appRoleId": wk.DIRECTORY_READ_ALL,
        },
        {
            "id": "opaque-2",
            "principalId": pid(100),
            "resourceId": pid(900),
            "appRoleId": pid(901),
            "resourceDisplayName": "unknown api",
        },
    ]
    assert graph.parse_app_role_assignments(b, items, roles, PROV) == []
    snap = _build(b)
    values = {e.dst: e.app_role_value for e in snap.edges if e.type == "hasAppRole"}
    assert values == {pid(103): "Directory.Read.All", pid(900): None}  # unknown stays unknown


def test_member_of_keeps_groups_only() -> None:
    b = SnapshotBuilder()
    b.entity(pid(100), "servicePrincipal")
    items = [
        {"@odata.type": "#microsoft.graph.group", "id": pid(120)},
        {"@odata.type": "#microsoft.graph.directoryRole", "id": pid(121)},
    ]
    assert graph.parse_member_of(b, pid(100), items, PROV) == []
    assert [e.dst for e in _build(b).edges] == [pid(120)]


def test_owner_of_unknown_type_is_reported() -> None:
    b = SnapshotBuilder()
    b.entity(pid(300), "application")
    errors = graph.parse_owners(
        b, pid(300), [{"@odata.type": "#microsoft.graph.device", "id": pid(1)}], PROV
    )
    assert errors == ["unknown-object-type"]


def test_directory_role_assignments_keep_scope() -> None:
    b = SnapshotBuilder()
    b.entity(pid(100), "servicePrincipal")
    graph.parse_directory_role_definitions(
        b, [{"id": wk.GLOBAL_ADMINISTRATOR, "displayName": "GA", "isBuiltIn": True}]
    )
    graph.parse_directory_role_assignments(
        b,
        [
            {
                "id": "opaque-1",
                "principalId": pid(100),
                "roleDefinitionId": wk.GLOBAL_ADMINISTRATOR,
                "directoryScopeId": f"/{pid(300)}",
            }
        ],
        PROV,
    )
    (edge,) = _build(b).edges
    assert edge.directory_scope_id == f"/{pid(300)}"


@pytest.mark.parametrize("bad", ["../x", "x", pid(1) + "/owners"])
def test_graph_requests_only_accept_guids(bad: str) -> None:
    with pytest.raises(graph.ParseError):
        graph.sp_owners_request(bad)


# --- builder ------------------------------------------------------------------------


def test_lower_priority_wins_regardless_of_order() -> None:
    for order in ([PRIORITY_STUB, PRIORITY_PRIMARY], [PRIORITY_PRIMARY, PRIORITY_STUB]):
        b = SnapshotBuilder()
        for prio in order:
            etype: EntityType = (
                "managedIdentity" if prio == PRIORITY_PRIMARY else "servicePrincipal"
            )
            b.entity(pid(105), etype, display_name=str(prio), priority=prio)
        (ent,) = _build(b).entities
        assert ent.type == "managedIdentity"


def test_dangling_edges_are_dropped_and_reported() -> None:
    b = SnapshotBuilder()
    b.entity(pid(100), "servicePrincipal")
    b.edge({"type": "memberOf", "src": pid(100), "dst": pid(999)}, PROV)
    snap = _build(b)
    assert snap.edges == ()
    assert [n.surface for n in snap.coverage.not_collected] == ["edges"]


@given(st.permutations(list(range(6))))
def test_builder_is_order_independent(order: list[int]) -> None:
    facts: list[Callable[[SnapshotBuilder], object]] = [
        lambda b: b.entity(pid(100), "servicePrincipal", display_name="a"),
        lambda b: b.entity(pid(100), "servicePrincipal", display_name="b", priority=PRIORITY_STUB),
        lambda b: b.entity(pid(120), "group"),
        lambda b: b.edge({"type": "memberOf", "src": pid(100), "dst": pid(120)}, PROV),
        lambda b: b.edge(
            {"type": "memberOf", "src": pid(100), "dst": pid(120)},
            Provenance(source_api="other", observed_at=PROV.observed_at),
        ),
        lambda b: b.entity(pid(120), "group", display_name="g"),
    ]
    ref = SnapshotBuilder()
    for f in facts:
        f(ref)
    b = SnapshotBuilder()
    for i in order:
        facts[i](b)
    assert _build(b).digest() == _build(ref).digest()
