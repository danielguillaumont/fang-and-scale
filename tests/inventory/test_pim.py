"""M3 E1: PIM eligibility, and 'not applicable' only with evidence. Mocked responses
on top of the demo fixture; no Azure."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from fns.adapters.azure import arm, graph
from fns.adapters.azure.http import ApiResponse
from fns.fixtures import wellknown as wk
from fns.fixtures.replay import FixtureSet, FixtureTransport, bundled, request_key
from fns.inventory.builder import SnapshotBuilder
from fns.inventory.collector import PIM_COLLECTOR, PIM_ELIGIBILITY, Collector
from fns.models.scope import parse_scope
from fns.models.snapshot import HasEligibleRole, Snapshot
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal
from tests.factories import pid

DEMO = FixtureSet.load(bundled("demo-scout"))
SUB = "00000000-0000-4000-8000-000000000010"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-fns-lab"
AGENT = pid(100)
USER = pid(4242)

DIR = graph.directory_role_eligibility_request()
SKUS = graph.subscribed_skus_request()
ARM = arm.role_eligibility_request(SUB)
NO_LICENCE = ApiResponse(
    400, {"error": {"code": "AadPremiumLicenseRequired", "message": "needs a licence"}}
)


def _sku(part: str, *plans: tuple[str, str]) -> dict[str, Any]:
    return {
        "skuId": pid(6000),
        "skuPartNumber": part,
        "capabilityStatus": "Enabled",
        "servicePlans": [
            {"servicePlanName": n, "servicePlanId": i, "provisioningStatus": "Success"}
            for n, i in plans
        ],
    }


FREE = ApiResponse(
    200, {"value": [_sku("O365_BUSINESS_ESSENTIALS", ("EXCHANGE_S_STANDARD", pid(1)))]}
)
P2 = ApiResponse(
    200,
    {"value": [_sku("EMSPREMIUM", ("AAD_PREMIUM_P2", "eec0eb4f-6444-4f95-aba0-50c24d67f998"))]},
)
EMPTY = ApiResponse(200, {"value": []})


def _dir_row(principal: str, role: str = wk.GLOBAL_ADMINISTRATOR) -> dict[str, Any]:
    return {
        "id": pid(8000),
        "principalId": principal,
        "roleDefinitionId": role,
        "directoryScopeId": "/",
    }


def _arm_row(principal: str) -> dict[str, Any]:
    rd = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{wk.OWNER}"
    return {
        "id": f"{RG}/providers/Microsoft.Authorization/roleEligibilitySchedules/{pid(8100)}",
        "properties": {
            "principalId": principal,
            "principalType": "ServicePrincipal",
            "roleDefinitionId": rd,
            "scope": RG,
        },
    }


def _fixture(
    responses: dict[str, ApiResponse],
    ops: tuple[str, ...] = (*arm.PIM_OPERATIONS, *graph.PIM_OPERATIONS),
) -> FixtureSet:
    urls = {"dir": DIR.url, "skus": SKUS.url, "arm": ARM.url}
    exchanges = [*DEMO.exchanges, *((request_key("GET", urls[k]), r) for k, r in responses.items())]
    scope = DEMO.scope_yaml.replace(
        "    - graph:GET /servicePrincipals\n",
        "".join(f"    - {op}\n" for op in ops) + "    - graph:GET /servicePrincipals\n",
    )
    return replace(DEMO, exchanges=tuple(exchanges), scope_yaml=scope)


def _run(fixture: FixtureSet) -> tuple[Snapshot, FixtureTransport]:
    clock = FrozenClock(fixture.recorded_at)
    manifest = parse_scope(fixture.scope_yaml, now=clock.now())
    gate = Gate(
        manifest, signed_in_tenant=str(manifest.tenant_id), journal=InMemoryJournal(), clock=clock
    )
    transport = FixtureTransport(fixture)
    snap = Collector(
        manifest=manifest,
        gate=gate,
        transport=transport,
        clock=clock,
        mode="FIXTURE",
        sleep=clock.advance,
    ).run()
    return snap, transport


def _status(snap: Snapshot) -> str:
    (run,) = [c for c in snap.coverage.collectors if c.name == PIM_COLLECTOR]
    return run.status


def _surface(snap: Snapshot) -> tuple[str, str]:
    """('collected' | 'not-applicable' | 'not-collected', reason)."""
    cov = snap.coverage
    for n in cov.not_collected:
        if n.surface == PIM_ELIGIBILITY:
            return "not-collected", n.reason
    for a in cov.not_applicable:
        if a.surface == PIM_ELIGIBILITY:
            return "not-applicable", a.reason
    return "collected", ""


def _eligible(snap: Snapshot) -> list[HasEligibleRole]:
    return [e for e in snap.edges if isinstance(e, HasEligibleRole)]


def test_scope_without_pim_ops_makes_no_requests_and_keeps_the_gap() -> None:
    snap, _ = _run(_fixture({}, ops=()))
    assert PIM_COLLECTOR not in {c.name for c in snap.coverage.collectors}
    assert _surface(snap)[0] == "not-collected"
    assert not snap.coverage.not_applicable


def test_eligibility_is_collected_for_principals_in_the_snapshot_only() -> None:
    dir_body = {"value": [_dir_row(AGENT), _dir_row(USER)]}
    snap, _ = _run(
        _fixture(
            {
                "dir": ApiResponse(200, dir_body),
                "arm": ApiResponse(200, {"value": [_arm_row(AGENT)]}),
            }
        )
    )
    assert _status(snap) == "complete"
    assert _surface(snap)[0] == "collected"
    edges = _eligible(snap)
    assert {(e.plane, e.src) for e in edges} == {("directory", AGENT), ("arm", AGENT)}
    (d,) = [e for e in edges if e.plane == "directory"]
    assert (d.dst, d.directory_scope_id) == (wk.GLOBAL_ADMINISTRATOR, "/")
    (a,) = [e for e in edges if e.plane == "arm"]
    assert a.dst == RG.lower() and a.role_definition_id.endswith(wk.OWNER)


def test_empty_listings_close_the_surface_without_asking_for_licences() -> None:
    snap, _ = _run(_fixture({"dir": EMPTY, "arm": EMPTY}))
    assert (_status(snap), _surface(snap)[0]) == ("complete", "collected")
    assert not snap.coverage.not_applicable


def test_no_pim_licence_is_not_applicable_with_the_responses_as_evidence() -> None:
    snap, _ = _run(_fixture({"dir": NO_LICENCE, "arm": EMPTY, "skus": FREE}))
    assert _status(snap) == "not-applicable"
    assert _surface(snap)[0] == "not-applicable"
    (na,) = snap.coverage.not_applicable
    text = "\n".join(na.evidence)
    assert "roleEligibilitySchedules -> http-400 AadPremiumLicenseRequired" in text
    assert f"/subscriptions/{SUB} -> ok" in text
    assert "O365_BUSINESS_ESSENTIALS" in text and "may carry PIM: none" in text


@pytest.mark.parametrize(
    ("responses", "why"),
    [
        # a licence that carries PIM: the failure is real, not 'no PIM here'
        ({"dir": NO_LICENCE, "arm": EMPTY, "skus": P2}, "EMSPREMIUM/AAD_PREMIUM_P2"),
        # licences unknown: never assume
        ({"dir": NO_LICENCE, "arm": EMPTY, "skus": ApiResponse(403, {})}, "cannot be ruled out"),
        # ARM returned a row: eligibility exists even without the licence we saw
        (
            {"dir": NO_LICENCE, "arm": ApiResponse(200, {"value": [_arm_row(USER)]}), "skus": FREE},
            "http-400",
        ),
    ],
)
def test_otherwise_it_stays_not_collected(responses: dict[str, ApiResponse], why: str) -> None:
    snap, _ = _run(_fixture(responses))
    state, reason = _surface(snap)
    assert state == "not-collected" and why in reason, reason
    assert _status(snap) in {"partial", "failed"}
    assert not snap.coverage.not_applicable


def test_licences_alone_are_not_enough_evidence() -> None:
    """Without an eligibility listing response there is nothing to explain."""
    snap, _ = _run(_fixture({"skus": FREE}, ops=graph.PIM_OPERATIONS[1:]))
    assert _surface(snap)[0] == "not-collected"
    assert "is not in the scope" in _surface(snap)[1]


def test_skus_not_in_scope_keeps_the_gap() -> None:
    ops = (*arm.PIM_OPERATIONS, graph.OP_DIR_ROLE_ELIGIBILITY)
    snap, _ = _run(_fixture({"dir": NO_LICENCE, "arm": EMPTY}, ops=ops))
    state, reason = _surface(snap)
    assert state == "not-collected" and "cannot be ruled out" in reason


def test_pim_licence_matcher_is_broad() -> None:
    skus, pim = graph.pim_licences(
        [
            _sku("ENTRA_ID_GOVERNANCE"),
            _sku("SPE_E5", ("SOMETHING", "eec0eb4f-6444-4f95-aba0-50c24d67f998")),
            {**_sku("AAD_PREMIUM_P2"), "capabilityStatus": "Deleted"},
            _sku("SPE_E3", ("AAD_PREMIUM", pid(2))),
        ]
    )
    assert skus == ["ENTRA_ID_GOVERNANCE", "SPE_E3", "SPE_E5"]
    assert pim == ["ENTRA_ID_GOVERNANCE", "SPE_E5/SOMETHING"]


def test_bad_eligibility_rows_are_errors_not_edges() -> None:
    b = SnapshotBuilder()
    b.entity(AGENT, "servicePrincipal")
    prov_snap, _ = _run(_fixture({"dir": EMPTY, "arm": EMPTY}))
    prov = prov_snap.edges[0].provenance
    skipped, errors = graph.parse_directory_role_eligibility(
        b, [{"principalId": "nope"}, _dir_row(USER)], prov
    )
    assert (skipped, errors) == (1, ["bad-item"])
