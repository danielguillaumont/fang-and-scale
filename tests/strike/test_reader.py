"""The scout reader: every strike read is a gated scout GET, by ID."""

from __future__ import annotations

import pytest

from fns.adapters.azure.http import ApiRequest, ApiResponse
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal, ScopeDeniedError
from fns.strike.reader import ReadError, ScoutReader
from tests.factories import NOW, TENANT
from tests.scope.writekit import APP_ESC, PAYROLL, VAULT
from tests.strike.faketenant import FakeReads, FakeTenant, manifest


def reader(scout_ops: list[str] | None = None) -> tuple[ScoutReader, FakeReads, InMemoryJournal]:
    m = manifest()
    if scout_ops is not None:
        ops = dict(m.allowed_operations)
        ops["scout"] = tuple(scout_ops)
        m = manifest(allowed_operations={k: list(v) for k, v in ops.items()})
    journal = InMemoryJournal()
    gate = Gate(m, signed_in_tenant=TENANT, journal=journal, clock=FrozenClock(NOW))
    reads = FakeReads(FakeTenant())
    return ScoutReader(gate, reads, TENANT), reads, journal


def test_reads_are_scout_gets_by_id() -> None:
    r, reads, journal = reader()
    assert r.storage_account(PAYROLL)["name"] == "stpayrolltest"
    assert r.vault(VAULT)["name"] == "kv-crown-jewels"
    assert r.application(APP_ESC)["id"] == APP_ESC
    assert r.app_owners(APP_ESC)
    urls = [q.url for q in reads.fetched]
    assert urls[0].endswith(f"{PAYROLL}?api-version=2023-05-01")
    assert urls[1].endswith(f"{VAULT}?api-version=2023-07-01")
    assert f"$filter=id%20eq%20%27{APP_ESC}%27" in urls[2] and "passwordCredentials" in urls[2]
    assert urls[3].endswith(f"/applications/{APP_ESC}/owners?$select=id")
    assert all(q.method == "GET" for q in reads.fetched)
    assert [d.verb for d in journal.decisions] == ["scout"] * 4
    assert all(d.decision == "allowed" for d in journal.decisions)


def test_a_read_outside_the_scout_operations_is_denied_and_not_sent() -> None:
    r, reads, _ = reader(["graph:GET /applications"])
    with pytest.raises(ScopeDeniedError):
        r.vault(VAULT)
    assert reads.fetched == []


def test_not_exactly_one_object() -> None:
    r, _, _ = reader()
    with pytest.raises(ReadError, match="exactly one"):
        r.application("00000000-0000-4000-8000-000000000999")


def test_a_non_guid_never_reaches_a_url() -> None:
    r, reads, _ = reader()
    with pytest.raises(ValueError):
        r.application("x' or 1 eq 1 or id eq '")
    assert reads.fetched == []


def test_an_error_status_is_a_read_error() -> None:
    r, reads, _ = reader()

    def fail(request: ApiRequest) -> ApiResponse:
        return ApiResponse(403, {})

    reads.fetch = fail  # type: ignore[method-assign]
    with pytest.raises(ReadError, match="403"):
        r.vault(VAULT)
