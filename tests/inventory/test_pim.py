"""M3 E1: PIM eligibility, and 'not applicable' only with evidence. Mocked responses
on top of the demo fixture; no Azure."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

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


def _sku(part: str, *plans: tuple[str, str], status: str = "Success") -> dict[str, Any]:
    return {
        "skuId": pid(6000),
        "skuPartNumber": part,
        "capabilityStatus": "Enabled",
        "servicePlans": [
            {"servicePlanName": n, "servicePlanId": i, "provisioningStatus": status}
            for n, i in plans
        ],
    }


P2_PLAN = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
EXCHANGE = pid(1)


FREE = ApiResponse(
    200, {"value": [_sku("O365_BUSINESS_ESSENTIALS", ("EXCHANGE_S_STANDARD", EXCHANGE))]}
)
P2 = ApiResponse(200, {"value": [_sku("EMSPREMIUM", ("AAD_PREMIUM_P2", P2_PLAN))]})
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


def test_no_licences_at_all_is_not_applicable_with_the_responses_as_evidence() -> None:
    """The lab's case: Entra ID Free, 0 SKUs, and the listing says a licence is needed."""
    snap, _ = _run(_fixture({"dir": NO_LICENCE, "arm": EMPTY, "skus": EMPTY}))
    assert _status(snap) == "not-applicable"
    assert _surface(snap)[0] == "not-applicable"
    (na,) = snap.coverage.not_applicable
    text = "\n".join(na.evidence)
    assert "roleEligibilitySchedules -> http-400 AadPremiumLicenseRequired" in text
    assert f"/subscriptions/{SUB} -> ok" in text
    assert "GET /subscribedSkus -> ok: 0 SKU(s) [none]; plans that may carry PIM: none" in text
    assert "not known to be PIM-free" not in text


def test_plans_known_by_id_to_be_pim_free_are_not_applicable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(graph, "PIM_FREE_PLAN_IDS", frozenset({EXCHANGE}))
    snap, _ = _run(_fixture({"dir": NO_LICENCE, "arm": EMPTY, "skus": FREE}))
    assert _surface(snap)[0] == "not-applicable"
    (na,) = snap.coverage.not_applicable
    assert "O365_BUSINESS_ESSENTIALS" in "\n".join(na.evidence)
    assert "no subscribed licence carries PIM" in na.reason


def test_the_pim_free_list_starts_empty() -> None:
    """Entries need a verified ID, plan name and source (graph.PIM_FREE_PLAN_IDS)."""
    assert frozenset() == graph.PIM_FREE_PLAN_IDS


@pytest.mark.parametrize(
    ("responses", "why"),
    [
        # a licence that carries PIM: the failure is real, not 'no PIM here'
        ({"dir": NO_LICENCE, "arm": EMPTY, "skus": P2}, "EMSPREMIUM/AAD_PREMIUM_P2"),
        # a plan not known (by ID) to be PIM-free: never assume
        (
            {"dir": NO_LICENCE, "arm": EMPTY, "skus": FREE},
            "not known to be PIM-free, so PIM cannot be ruled out: "
            "O365_BUSINESS_ESSENTIALS/EXCHANGE_S_STANDARD",
        ),
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


def test_the_matcher_uses_plan_ids_never_names() -> None:
    free = frozenset({EXCHANGE, pid(2)})
    lic = graph.pim_licences(
        [
            # named like P2, but its only plan is known PIM-free: names are ignored
            _sku("AAD_PREMIUM_P2_LOOKALIKE", ("AAD_PREMIUM_P2", EXCHANGE)),
            # P2's plan ID under another name is still P2
            _sku("SPE_E5", ("SOMETHING", P2_PLAN)),
            # a disabled plan still counts: skipping it would loosen not-applicable
            _sku("EMS", ("AAD_PREMIUM_P2", P2_PLAN), status="Disabled"),
            # a deleted SKU is gone
            {**_sku("ENTRA_ID_GOVERNANCE", ("X", pid(9))), "capabilityStatus": "Deleted"},
            _sku("SPE_E3", ("AAD_PREMIUM", pid(2))),
        ],
        pim_free=free,
    )
    assert lic.skus == ("AAD_PREMIUM_P2_LOOKALIKE", "EMS", "SPE_E3", "SPE_E5")
    assert lic.pim == ("EMS/AAD_PREMIUM_P2", "SPE_E5/SOMETHING")
    assert lic.unknown == ()
    assert not lic.rules_out_pim


@pytest.mark.parametrize(
    ("sku", "unknown"),
    [
        (_sku("ENTRA_ID_GOVERNANCE"), "ENTRA_ID_GOVERNANCE/(no service plans)"),
        (_sku("NEW_SKU", ("NEW_PLAN", pid(77))), "NEW_SKU/NEW_PLAN"),
        (_sku("NO_ID", ("SOME_PLAN", "")), "NO_ID/SOME_PLAN"),
        (_sku("BAD_ID", ("SOME_PLAN", "not-a-guid")), "BAD_ID/SOME_PLAN"),
        (_sku("NAMELESS", ("", pid(78))), f"NAMELESS/{pid(78)}"),
    ],
)
def test_unknown_skus_and_plans_never_rule_pim_out(sku: dict[str, Any], unknown: str) -> None:
    lic = graph.pim_licences([sku], pim_free=frozenset({EXCHANGE}))
    assert lic.unknown == (unknown,)
    assert not lic.rules_out_pim


PLAN_IDS = st.sampled_from([EXCHANGE, pid(2), pid(3), P2_PLAN, "", "not-a-guid"])
PLANS = st.lists(st.tuples(st.sampled_from(["A", "B", ""]), PLAN_IDS), max_size=4)
SKU = st.builds(
    lambda part, plans, status, deleted: {
        **_sku(part, *plans, status=status),
        "capabilityStatus": "Deleted" if deleted else "Enabled",
    },
    st.sampled_from(["AAD_PREMIUM_P2", "SPE_E3", "FREE"]),
    PLANS,
    st.sampled_from(["Success", "Disabled", "PendingActivation"]),
    st.booleans(),
)


@given(st.lists(SKU, max_size=5), st.sets(st.sampled_from([EXCHANGE, pid(2), pid(3)])))
def test_pim_is_ruled_out_only_when_every_live_plan_is_known_free(
    skus: list[dict[str, Any]], free: set[str]
) -> None:
    lic = graph.pim_licences(skus, pim_free=frozenset(free))
    live = [s for s in skus if s["capabilityStatus"] != "Deleted"]
    every_plan_known_free = all(
        s["servicePlans"] and all(p["servicePlanId"] in free for p in s["servicePlans"])
        for s in live
    )
    assert lic.rules_out_pim == every_plan_known_free


def test_bad_eligibility_rows_are_errors_not_edges() -> None:
    b = SnapshotBuilder()
    b.entity(AGENT, "servicePrincipal")
    prov_snap, _ = _run(_fixture({"dir": EMPTY, "arm": EMPTY}))
    prov = prov_snap.edges[0].provenance
    skipped, errors = graph.parse_directory_role_eligibility(
        b, [{"principalId": "nope"}, _dir_row(USER)], prov
    )
    assert (skipped, errors) == (1, ["bad-item"])
