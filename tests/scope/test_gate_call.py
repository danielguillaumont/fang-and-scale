from __future__ import annotations

from datetime import datetime
from typing import Literal

import pytest

from fns.scope.gate import DenyReason, GateRecord, InMemoryJournal, ScopeDeniedError
from fns.scope.targets import DirectoryTarget
from tests.factories import OTHER_TENANT, RG, RG2, TENANT
from tests.scope.gatekit import ARM_READ, ARM_URL, GRAPH_READ, GRAPH_URL, make_gate, manifest


class Spy:
    def __init__(self, result: object = "ok", exc: BaseException | None = None) -> None:
        self.calls = 0
        self.result = result
        self.exc = exc

    def __call__(self) -> object:
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        return self.result


@pytest.mark.parametrize(
    ("target", "tenant", "op", "url", "reason"),
    [
        (
            RG2,
            TENANT,
            ARM_READ,
            ARM_URL.replace("rg-fns-lab", "rg-fns-other"),
            DenyReason.RG_NOT_ALLOWED,
        ),
        (RG, OTHER_TENANT, ARM_READ, ARM_URL, DenyReason.TENANT_MISMATCH),
        (
            RG,
            TENANT,
            ARM_READ,
            ARM_URL.replace("management.azure.com", "evil.example"),
            DenyReason.BAD_URL,
        ),
        (
            RG,
            TENANT,
            "arm:Microsoft.Authorization/roleAssignments/write",
            ARM_URL,
            DenyReason.OPERATION_NOT_ALLOWED,
        ),
    ],
)
def test_fn_never_invoked_on_deny(
    target: str, tenant: str, op: str, url: str, reason: DenyReason
) -> None:
    gate, journal, _ = make_gate()
    spy = Spy()
    with pytest.raises(ScopeDeniedError) as info:
        gate.call("scout", op, target, tenant, spy, url=url)
    assert spy.calls == 0
    assert info.value.decision.reason is reason
    assert gate.calls_used == 0
    assert [d.decision for d in journal.decisions] == ["denied"]
    assert journal.decisions[0].reason == reason.value
    assert journal.results == []


def test_allowed_call_runs_and_is_journaled() -> None:
    gate, journal, _ = make_gate()
    spy = Spy("payload")
    assert gate.call("scout", ARM_READ, RG, TENANT, spy, url=ARM_URL) == "payload"
    assert spy.calls == 1
    assert gate.calls_used == 1
    rec = journal.decisions[0]
    assert (rec.decision, rec.verb, rec.operation, rec.url, rec.seq) == (
        "allowed",
        "scout",
        ARM_READ,
        ARM_URL,
        1,
    )
    assert journal.results == [("run-test", 1, "succeeded", "")]


def test_graph_call_through_gate() -> None:
    gate, _, _ = make_gate()
    assert gate.call("scout", GRAPH_READ, DirectoryTarget(), TENANT, lambda: 7, url=GRAPH_URL) == 7


def test_budget_consumed_even_when_fn_raises() -> None:
    gate, journal, _ = make_gate(manifest(budget={"max_api_calls": 1, "max_minutes": 5}))
    with pytest.raises(TimeoutError):
        gate.call("scout", ARM_READ, RG, TENANT, Spy(exc=TimeoutError()), url=ARM_URL)
    assert gate.calls_used == 1
    assert journal.results == [("run-test", 1, "failed", "TimeoutError")]
    with pytest.raises(ScopeDeniedError) as info:
        gate.call("scout", ARM_READ, RG, TENANT, Spy(), url=ARM_URL)
    assert info.value.decision.reason is DenyReason.BUDGET_CALLS


def test_denied_and_allowed_both_journaled_in_order() -> None:
    gate, journal, _ = make_gate()
    gate.call("scout", ARM_READ, RG, TENANT, Spy(), url=ARM_URL)
    with pytest.raises(ScopeDeniedError):
        gate.call("scout", ARM_READ, RG2, TENANT, Spy(), url=ARM_URL)
    gate.call("scout", ARM_READ, RG, TENANT, Spy(), url=ARM_URL)
    assert [(d.seq, d.decision) for d in journal.decisions] == [
        (1, "allowed"),
        (2, "denied"),
        (3, "allowed"),
    ]


def test_off_host_next_link_denied() -> None:
    gate, _, _ = make_gate()
    spy = Spy()
    first = ARM_URL
    gate.call("scout", ARM_READ, RG, TENANT, spy, url=first)
    evil = (
        "https://evil.example"
        + first.removeprefix("https://management.azure.com")
        + "&$skiptoken=x"
    )
    with pytest.raises(ScopeDeniedError) as info:
        gate.call("scout", ARM_READ, RG, TENANT, spy, url=evil, page_of=first)
    assert info.value.decision.reason is DenyReason.BAD_URL
    assert spy.calls == 1


def test_next_link_that_moves_path_denied() -> None:
    gate, _, _ = make_gate()
    moved = ARM_URL.replace("roleAssignments", "roleDefinitions") + "&$skiptoken=x"
    with pytest.raises(ScopeDeniedError) as info:
        gate.call("scout", ARM_READ, RG, TENANT, Spy(), url=moved, page_of=ARM_URL)
    assert info.value.decision.reason is DenyReason.BAD_URL


def test_valid_next_link_allowed() -> None:
    gate, _, _ = make_gate()
    nxt = ARM_URL + "&$skiptoken=abc"
    assert gate.call("scout", ARM_READ, RG, TENANT, lambda: 1, url=nxt, page_of=ARM_URL) == 1


class FailingJournal(InMemoryJournal):
    def record_decision(self, record: GateRecord) -> None:
        raise OSError("disk full")


def test_journal_failure_denies_and_skips_call() -> None:
    gate, _, _ = make_gate(journal=FailingJournal())
    spy = Spy()
    with pytest.raises(ScopeDeniedError) as info:
        gate.call("scout", ARM_READ, RG, TENANT, spy, url=ARM_URL)
    assert info.value.decision.reason is DenyReason.JOURNAL_FAILED
    assert spy.calls == 0
    assert gate.calls_used == 0


def test_journal_records_utc_timestamps() -> None:
    seen: list[datetime] = []

    class Capture(InMemoryJournal):
        def record_call_result(
            self,
            run_id: str,
            seq: int,
            status: Literal["succeeded", "failed"],
            detail: str,
            at: datetime,
        ) -> None:
            seen.append(at)

    gate, journal, _ = make_gate(journal=Capture())
    gate.call("scout", ARM_READ, RG, TENANT, Spy(), url=ARM_URL)
    assert journal.decisions[0].at.utcoffset() is not None
    assert seen and seen[0].utcoffset() is not None
