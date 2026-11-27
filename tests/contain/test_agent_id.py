"""Entra Agent ID: recognised by the collector, and never assessed until inheritance is
modeled (approved 2026-11-27; docs/milestones/M6-agent-id.md, "The gap today").

An agent identity's reach is its own grants plus what it inherits from its blueprint
principal, and the model reads only the first part. So when the attacker controls an
Agent ID object, every finding the model cannot settle is ``not-assessed``, a pass
is impossible at any rung, and a modeled reach still fails (inheritance only adds).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from fns.adapters.azure import graph
from fns.contain.evaluate import evaluate
from fns.contain.report import build_report
from fns.inventory.builder import SnapshotBuilder
from fns.models.assertions import ProbeObservation
from fns.models.contract import Contract
from fns.models.evidence import Finding
from fns.models.snapshot import (
    AGENT_ID_NOT_MODELED,
    AGENT_ID_ODATA_TYPES,
    AGENT_ID_PROPERTY,
    Provenance,
    Snapshot,
    SnapshotCoverage,
)
from fns.prove.freeze import AGENT_ID_INHERITANCE, freeze
from fns.verify.verdict import judge
from tests.contain.helpers import AGENT, KV, Snap, contract
from tests.factories import NOW, TENANT, pid

PROV = Provenance(source_api="test", observed_at=datetime(2026, 11, 27, tzinfo=UTC))
AGENT_IDENTITY = "#microsoft.graph.agentIdentity"
BLUEPRINT = "#microsoft.graph.agentIdentityBlueprint"
BLUEPRINT_PRINCIPAL = "#microsoft.graph.agentIdentityBlueprintPrincipal"
SECRET_GET = {"resource": "kv-crown", "operations": ["secrets/get"]}


# --- the collector --------------------------------------------------------------------


def _sp(odata: str | None, **extra: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"id": pid(300), "appId": pid(301), "displayName": "agent-x", **extra}
    if odata is not None:
        item["@odata.type"] = odata
    return item


def _entity(b: SnapshotBuilder, oid: str) -> Any:
    snap = b.build(
        mode="FIXTURE",
        tenant_id=TENANT,
        collected_at=PROV.observed_at,
        collector_version="t",
        coverage=SnapshotCoverage(collectors=(), not_collected=()),
    )
    return next(e for e in snap.entities if e.id == oid)


def test_the_three_odata_types_are_the_documented_ones() -> None:
    assert set(AGENT_ID_ODATA_TYPES) == {AGENT_IDENTITY, BLUEPRINT, BLUEPRINT_PRINCIPAL}


@pytest.mark.parametrize(
    ("odata", "kind"),
    [(AGENT_IDENTITY, "agentIdentity"), (BLUEPRINT_PRINCIPAL, "agentIdentityBlueprintPrincipal")],
)
def test_agent_service_principals_are_marked_and_stay_service_principals(
    odata: str, kind: str
) -> None:
    b = SnapshotBuilder()
    _, errors = graph.parse_service_principals(b, [_sp(odata)])
    assert errors == []
    e = _entity(b, pid(300))
    assert (e.type, e.properties[AGENT_ID_PROPERTY]) == ("servicePrincipal", kind)


def test_an_agent_identity_is_never_typed_as_a_managed_identity() -> None:
    b = SnapshotBuilder()
    graph.parse_service_principals(b, [_sp(AGENT_IDENTITY, servicePrincipalType="ManagedIdentity")])
    assert _entity(b, pid(300)).type == "servicePrincipal"


def test_a_blueprint_application_is_marked() -> None:
    b = SnapshotBuilder()
    item = {"@odata.type": BLUEPRINT, "id": pid(310), "appId": pid(301), "displayName": "bp"}
    assert graph.parse_applications(b, [item], {}, PROV) == []
    e = _entity(b, pid(310))
    assert (e.type, e.properties[AGENT_ID_PROPERTY]) == ("application", "agentIdentityBlueprint")


@pytest.mark.parametrize(
    "odata", [None, "#microsoft.graph.servicePrincipal", BLUEPRINT, "#microsoft.graph.agentX"]
)
def test_anything_else_gets_no_marker(odata: str | None) -> None:
    """Plain objects keep their exact properties (so existing digests stay), and a
    blueprint type in the service principal listing is not a service principal kind."""
    b = SnapshotBuilder()
    graph.parse_service_principals(b, [_sp(odata)])
    assert AGENT_ID_PROPERTY not in _entity(b, pid(300)).properties


def test_an_agent_identity_owner_is_recognised() -> None:
    b = SnapshotBuilder()
    b.entity(pid(310), "application")
    errors = graph.parse_owners(
        b, pid(310), [{"@odata.type": AGENT_IDENTITY, "id": pid(300)}], PROV
    )
    assert errors == []
    e = _entity(b, pid(300))
    assert (e.type, e.properties[AGENT_ID_PROPERTY]) == ("servicePrincipal", "agentIdentity")


# --- contain --------------------------------------------------------------------------


def _world(agent_kind: str | None = None) -> Snap:
    """Nothing reaches the vault and every collector is complete: without Agent ID the
    only result is "not reachable in the model"."""
    s = Snap()
    s.sp(100, "sp-agent")
    if agent_kind is not None:
        s.entities[AGENT]["properties"][AGENT_ID_PROPERTY] = agent_kind
    s.kv(enableRbacAuthorization=True)
    return s


def _findings(snapshot: Snapshot, c: Contract) -> list[Finding]:
    return [o.finding for o in evaluate(c, snapshot).outcomes]


def _open(snapshot: Snapshot, c: Contract) -> list[tuple[str, ...]]:
    report = build_report(evaluate(c, snapshot), generated_at=NOW, tool_version="test")
    return [a.open_surfaces for a in freeze(c, snapshot, report, frozen_at=NOW).assertions]


def _has_reason(f: Finding) -> bool:
    return any(r.startswith(AGENT_ID_NOT_MODELED) for r in f.reasons)


def test_a_plain_service_principal_is_unchanged() -> None:
    snap = _world().build()
    (f,) = _findings(snap, contract([SECRET_GET]))
    assert (f.verdict, f.coverage) == ("inconclusive", "modeled-only")
    assert not _has_reason(f)
    assert _open(snap, contract([SECRET_GET])) == [()]


@pytest.mark.parametrize(
    "kind", ["agentIdentity", "agentIdentityBlueprintPrincipal", "agentIdentityBlueprint"]
)
def test_a_compromised_agent_id_object_is_not_assessed(kind: str) -> None:
    snap = _world(kind).build()
    c = contract([SECRET_GET])
    (f,) = _findings(snap, c)
    assert (f.verdict, f.coverage) == ("inconclusive", "not-assessed")
    assert _has_reason(f), f.reasons
    assert _open(snap, c) == [(AGENT_ID_INHERITANCE,)]


def test_must_still_do_is_not_failed_on_a_model_that_misses_inheritance() -> None:
    """Without Agent ID this would fail ("nothing in the model grants it"). The
    inherited grants may well allow it, so the model cannot say."""
    still = {"resource": "kv-crown", "operations": ["secrets/list"]}
    c = contract([SECRET_GET], [still])

    def still_do(snap: Snapshot) -> list[Finding]:
        return [f for f in _findings(snap, c) if f.item_kind == "must_still_do"]

    plain = still_do(_world().build())
    agent = still_do(_world("agentIdentity").build())
    assert [(f.verdict, f.coverage) for f in plain] == [("fail", "modeled-only")]
    assert [(f.verdict, f.coverage) for f in agent] == [("inconclusive", "not-assessed")]
    assert _has_reason(agent[0])


def test_a_modeled_reach_still_fails_and_says_why_it_may_be_larger() -> None:
    s = _world("agentIdentity")
    s.rbac(AGENT, "Key Vault Secrets Officer", KV)
    (f,) = _findings(s.build(), contract([SECRET_GET]))
    assert (f.verdict, f.coverage) == ("fail", "modeled-only")
    assert _has_reason(f)


def test_controlling_an_agent_identity_counts_too() -> None:
    """The attacker owns an agent identity and can add a credential to it: what that
    identity inherits is just as invisible."""
    s = _world()
    other = s.entity(pid(300), "servicePrincipal", "agent-x", appId=pid(301))
    s.entities[other]["properties"][AGENT_ID_PROPERTY] = "agentIdentity"
    s.graph_perm(AGENT, "Application.ReadWrite.OwnedBy")
    s.edge("owns", AGENT, other)
    snap = s.build()
    (f,) = _findings(snap, contract([SECRET_GET]))
    assert (f.verdict, f.coverage) == ("inconclusive", "not-assessed")
    assert any("agent-x is an agent identity" in r for r in f.reasons), f.reasons


def test_the_service_principal_of_a_blueprint_counts() -> None:
    s = _world()
    app = s.app(310, "bp-app", sp=AGENT)
    s.entities[app]["properties"][AGENT_ID_PROPERTY] = "agentIdentityBlueprint"
    (f,) = _findings(s.build(), contract([SECRET_GET]))
    assert f.coverage == "not-assessed"
    assert any("service principal of an agent identity blueprint" in r for r in f.reasons)


def test_an_agent_identity_the_attacker_does_not_control_changes_nothing() -> None:
    s = _world()
    other = s.entity(pid(300), "servicePrincipal", "agent-x", appId=pid(301))
    s.entities[other]["properties"][AGENT_ID_PROPERTY] = "agentIdentity"
    (f,) = _findings(s.build(), contract([SECRET_GET]))
    assert (f.verdict, f.coverage) == ("inconclusive", "modeled-only")


# --- prove ----------------------------------------------------------------------------


def _denied_everywhere(snapshot: Snapshot, c: Contract) -> Finding:
    report = build_report(evaluate(c, snapshot), generated_at=NOW, tool_version="test")
    (a,) = freeze(c, snapshot, report, frozen_at=NOW).assertions
    obs = {
        s.id: (
            ProbeObservation(
                version=1,
                mode="FIXTURE",
                probe_id=s.id,
                finding_id=a.finding_id,
                kind=s.kind,
                rung=s.rung,
                outcome="denied",
                observed_at=NOW,
            ),
            "b" * 64,
        )
        for s in a.probes
    }
    assert any(s.kind == "data-read" for s in a.probes)  # rung 3 is on the table
    return judge(a, obs, c.contract)


def test_an_observed_denial_passes_a_plain_identity_but_not_an_agent() -> None:
    c = contract([SECRET_GET])
    assert _denied_everywhere(_world().build(), c).verdict == "pass"
    f = _denied_everywhere(_world("agentIdentity").build(), c)
    assert (f.verdict, f.coverage) == ("inconclusive", "verified")
    assert any(AGENT_ID_INHERITANCE in r for r in f.reasons), f.reasons
