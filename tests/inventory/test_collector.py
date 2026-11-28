from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fns.adapters.azure import arm, graph
from fns.adapters.azure.http import ApiRequest, ApiResponse, TransportError
from fns.fixtures import wellknown as wk
from fns.fixtures.replay import FixtureSet, FixtureTransport, bundled
from fns.inventory.collector import MAX_BACKOFF_SECONDS, Collector
from fns.models.scope import ScopeManifest, parse_scope
from fns.models.snapshot import Snapshot
from fns.scope.gate import DenyReason, FrozenClock, Gate, InMemoryJournal
from tests.factories import OTHER_TENANT, pid

FIXTURE = FixtureSet.load(bundled("demo-scout"))
SP_AGENT, SP_VERIFIER, MI_AA, USER_ADMIN = pid(100), pid(101), pid(105), pid(110)


def _manifest(**changes: Any) -> ScopeManifest:
    clock = FrozenClock(FIXTURE.recorded_at)
    m = parse_scope(FIXTURE.scope_yaml, now=clock.now())
    if not changes:
        return m
    return ScopeManifest.model_validate({**m.model_dump(mode="json"), **changes})


@dataclass
class Run:
    snapshot: Snapshot
    gate: Gate
    journal: InMemoryJournal
    transport: Any
    slept: list[float] = field(default_factory=list)

    def collector(self, name: str) -> Any:
        (run,) = [c for c in self.snapshot.coverage.collectors if c.name == name]
        return run


def run(
    transport: Any = None,
    manifest: ScopeManifest | None = None,
    *,
    signed_in: str | None = None,
    max_retries: int = 3,
) -> Run:
    clock = FrozenClock(FIXTURE.recorded_at)
    manifest = manifest or _manifest()
    journal = InMemoryJournal()
    gate = Gate(
        manifest,
        signed_in_tenant=signed_in or str(manifest.tenant_id),
        journal=journal,
        clock=clock,
    )
    transport = transport if transport is not None else FixtureTransport(FIXTURE)
    slept: list[float] = []
    snap = Collector(
        manifest=manifest,
        gate=gate,
        transport=transport,
        clock=clock,
        mode="FIXTURE",
        sleep=slept.append,
        max_retries=max_retries,
    ).run()
    return Run(snap, gate, journal, transport, slept)


def _edges(snap: Snapshot, etype: str) -> list[Any]:
    return [e for e in snap.edges if e.type == etype]


# --- the demo fixture -----------------------------------------------------------------


def test_demo_fixture_collects_expected_graph() -> None:
    r = run()
    snap = r.snapshot
    assert snap.mode == "FIXTURE"
    assert len(snap.entities) == 21
    assert len(snap.edges) == 23
    assert r.transport.unused() == []
    statuses = {c.name: c.status for c in snap.coverage.collectors}
    assert statuses.pop("graph.directory-roles") == "failed"
    assert set(statuses.values()) == {"complete"}


def test_every_request_is_one_gated_call() -> None:
    r = run()
    assert r.gate.calls_used == len(r.transport.served) == 28
    assert all(rec.decision == "allowed" for rec in r.journal.decisions)
    assert len(r.journal.decisions) == 28


def test_paging_is_followed() -> None:
    snap = run().snapshot
    rbac = {(e.src, e.role_definition_id.rsplit("/", 1)[-1]) for e in _edges(snap, "hasRbacRole")}
    assert (USER_ADMIN, wk.OWNER) in rbac  # second page of role assignments
    assert any(e.id == MI_AA and e.type == "managedIdentity" for e in snap.entities)  # graph p2


def test_429_is_retried_after_retry_after() -> None:
    r = run()
    assert r.slept == [1]
    assert r.collector("graph.applications").status == "complete"


def test_403_is_recorded_not_raised() -> None:
    r = run()
    c = r.collector("graph.directory-roles")
    assert (c.status, c.error_codes, c.items) == ("failed", ("http-403",), 0)
    assert _edges(r.snapshot, "hasDirectoryRole") == []


def test_real_entities_beat_stubs() -> None:
    snap = run().snapshot
    by_id = {e.id: e for e in snap.entities}
    # Seen as an ARM principalType=ServicePrincipal stub and as a Graph managed identity.
    assert by_id[MI_AA].type == "managedIdentity"
    assert by_id[MI_AA].display_name == "aa-billing-runbooks"


def test_escalation_primitives_are_present() -> None:
    snap = run().snapshot
    assert any(e.type == "owns" and e.src == SP_AGENT and e.dst == pid(301) for e in snap.edges)
    assert any(
        e.type == "hasAppRole"
        and e.src == SP_AGENT
        and e.app_role_value == "Application.ReadWrite.OwnedBy"
        for e in snap.edges
    )
    (deny,) = _edges(snap, "denyAssignment")
    assert [str(p) for p in deny.excluded_principal_ids] == [SP_VERIFIER]


# --- scope and budget -----------------------------------------------------------------


def test_scope_denied_operation_is_skipped_without_touching_the_transport() -> None:
    m = _manifest()
    ops = [o for o in m.allowed_operations["scout"] if "roleManagement" not in o]
    r = run(manifest=_manifest(allowed_operations={"scout": ops}))
    c = r.collector("graph.directory-roles")
    assert (c.status, c.error_codes) == ("skipped", ("scope-denied",))
    assert not any("rolemanagement" in k for k in r.transport.served)
    assert any(d.reason == DenyReason.OPERATION_NOT_ALLOWED for d in r.journal.decisions)


def test_tenant_mismatch_denies_everything() -> None:
    r = run(signed_in=OTHER_TENANT)
    assert r.transport.served == []
    assert {c.status for c in r.snapshot.coverage.collectors} == {"skipped"}


def test_budget_exhaustion_degrades_coverage_instead_of_overrunning() -> None:
    m = _manifest()
    r = run(manifest=_manifest(budget={"max_api_calls": 5, "max_minutes": m.budget.max_minutes}))
    assert r.gate.calls_used == 5
    assert len(r.transport.served) == 5
    assert "skipped" in {c.status for c in r.snapshot.coverage.collectors}


# --- transport behaviours --------------------------------------------------------------


class Scripted:
    """Answers per URL substring; falls back to an empty list."""

    def __init__(self, rules: dict[str, list[ApiResponse | Exception]]) -> None:
        self.rules = rules
        self.served: list[str] = []

    def fetch(self, request: ApiRequest) -> ApiResponse:
        self.served.append(request.url)
        for needle, answers in self.rules.items():
            if needle in request.url:
                answer = answers.pop(0) if len(answers) > 1 else answers[0]
                if isinstance(answer, Exception):
                    raise answer
                return answer
        return ApiResponse(200, {"value": []}, None, None)


def ok(body: dict[str, Any]) -> ApiResponse:
    return ApiResponse(200, body, None, None)


def test_persistent_429_gives_up_and_every_retry_is_gated() -> None:
    t = Scripted({"/applications?": [ApiResponse(429, {}, None, 10_000.0)]})
    r = run(t, max_retries=2)
    c = r.collector("graph.applications")
    assert (c.status, c.error_codes) == ("failed", ("http-429-exhausted",))
    assert r.slept == [MAX_BACKOFF_SECONDS, MAX_BACKOFF_SECONDS]
    assert sum("/applications?" in u for u in t.served) == 3


def test_retry_without_retry_after_backs_off_exponentially() -> None:
    answers: list[ApiResponse | Exception] = [ApiResponse(503, {}, None, None)] * 3
    t = Scripted({"/applications?": [*answers, ok({"value": []})]})
    r = run(t)
    assert r.slept == [1.0, 2.0, 4.0]
    assert r.collector("graph.applications").status == "complete"


def test_transport_error_is_a_failure() -> None:
    t = Scripted({"/applications?": [TransportError("tls")]})
    c = run(t).collector("graph.applications")
    assert (c.status, c.error_codes) == ("failed", ("transport-error",))


def test_malformed_body_is_a_failure() -> None:
    t = Scripted({"/applications?": [ok({"value": "nope"})]})
    assert run(t).collector("graph.applications").error_codes == ("bad-response",)


def test_off_host_next_link_is_denied_and_never_fetched() -> None:
    t = Scripted(
        {
            "/applications?": [
                ok({"value": [], "@odata.nextLink": "https://evil.example/v1.0/applications"})
            ]
        }
    )
    r = run(t)
    c = r.collector("graph.applications")
    assert (c.status, c.error_codes) == ("failed", ("next-link-denied",))
    assert not any("evil" in u for u in t.served)
    assert any(d.reason == DenyReason.BAD_URL for d in r.journal.decisions)


def test_bad_items_make_a_collector_partial() -> None:
    t = Scripted(
        {
            "/applications?": [
                ok({"value": [{"id": "not-a-guid"}, {"id": pid(300), "appId": pid(200)}]})
            ]
        }
    )
    c = run(t).collector("graph.applications")
    assert (c.status, c.error_codes) == ("partial", ("bad-item",))


def test_unbounded_paging_stops() -> None:
    url = graph.applications_request().url
    t = Scripted({"/applications?": [ok({"value": [], "@odata.nextLink": url + "&$skiptoken=x"})]})
    c = run(t, manifest=_manifest(budget={"max_api_calls": 5000, "max_minutes": 15})).collector(
        "graph.applications"
    )
    assert c.error_codes == ("too-many-pages",)


# --- determinism ---------------------------------------------------------------------


class Shuffled:
    def __init__(self, seed: random.Random) -> None:
        self.inner = FixtureTransport(FIXTURE)
        self.rng = seed

    def fetch(self, request: ApiRequest) -> ApiResponse:
        resp = self.inner.fetch(request)
        value = resp.body.get("value")
        if isinstance(value, list):
            value = list(value)
            self.rng.shuffle(value)
            return ApiResponse(resp.status, {**resp.body, "value": value}, "rid", resp.retry_after)
        return resp

    def unused(self) -> list[str]:
        return self.inner.unused()


GOLDEN = run().snapshot.digest()


@settings(max_examples=25, deadline=None)
@given(st.randoms(use_true_random=False))
def test_digest_is_independent_of_item_order(rng: random.Random) -> None:
    assert run(Shuffled(rng)).snapshot.digest() == GOLDEN


def test_request_catalogue_matches_demo_scope() -> None:
    ops = set(_manifest().allowed_operations["scout"])
    assert ops == set(arm.ARM_OPERATIONS) | set(graph.GRAPH_OPERATIONS)


@pytest.mark.parametrize(
    "op",
    sorted(
        set(arm.ARM_OPERATIONS) | set(graph.GRAPH_OPERATIONS) | set(graph.CREDENTIAL_OPERATIONS)
    ),
)
def test_catalogue_is_read_only(op: str) -> None:
    from fns.models.operations import parse_operation

    assert parse_operation(op).is_read
