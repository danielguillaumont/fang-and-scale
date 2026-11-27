from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule

from fns.journal.sqlite import (
    NeedsReconcileError,
    SqliteJournal,
    StepConflictError,
)
from fns.scope.gate import GateRecord

T0 = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


class Crash(BaseException):
    """Stands in for a killed process: not an Exception, so nothing is recorded."""


@pytest.fixture
def journal(tmp_path: Path) -> Iterator[SqliteJournal]:
    with SqliteJournal(tmp_path / "j.sqlite", now=lambda: T0) as j:
        j.begin_run("r1", "scout", "FIXTURE")
        yield j


def _ident(x: str) -> str:
    return f"d:{x}"


def test_update_and_delete_are_rejected_on_every_table(journal: SqliteJournal) -> None:
    journal.run_step("r1", "s", "read", "GET x", lambda: "v", digest=_ident)
    journal.record_decision(
        GateRecord("r1", 1, "scout", "op", "t", "ten", None, None, "allowed", None, "", T0)
    )
    journal.record_call_result("r1", 1, "succeeded", "", T0)
    journal.strike_event("r1", "S1/list-keys", "intent", {"method": "POST"})
    conn = sqlite3.connect(journal.path)
    try:
        for table in (
            "runs",
            "steps",
            "step_events",
            "gate_decisions",
            "gate_results",
            "strike_events",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(f"DELETE FROM {table}")  # noqa: S608
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(f"UPDATE {table} SET run_id = 'x'")  # noqa: S608
    finally:
        conn.close()


def test_run_ids_are_unique(journal: SqliteJournal) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        journal.begin_run("r1", "scout", "FIXTURE")
    assert journal.has_run("r1")
    assert not journal.has_run("r2")


def test_mode_is_constrained(journal: SqliteJournal) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        journal.begin_run("r2", "scout", "MAYBE")  # type: ignore[arg-type]


def test_succeeded_step_is_skipped_and_returns_recorded_digest(journal: SqliteJournal) -> None:
    calls: list[int] = []

    def body() -> str:
        calls.append(1)
        return "value"

    first = journal.run_step("r1", "s", "write", "PUT x", body, digest=_ident)
    second = journal.run_step("r1", "s", "write", "PUT x", body, digest=_ident)
    assert first.status == "ran"
    assert first.value == "value"
    assert second.status == "skipped"
    assert second.value is None
    assert second.response_digest == first.response_digest == "d:value"
    assert calls == [1]


def test_failed_read_is_retried(journal: SqliteJournal) -> None:
    def boom() -> str:
        raise ValueError("transient")

    with pytest.raises(ValueError, match="transient"):
        journal.run_step("r1", "s", "read", "GET x", boom, digest=_ident)
    assert journal.step_status("r1", "s") == "failed"
    result = journal.run_step("r1", "s", "read", "GET x", lambda: "ok", digest=_ident)
    assert result.status == "ran"
    assert journal.step_status("r1", "s") == "succeeded"


def test_crashed_read_is_rerun(journal: SqliteJournal) -> None:
    def crash() -> str:
        raise Crash

    with pytest.raises(Crash):
        journal.run_step("r1", "s", "read", "GET x", crash, digest=_ident)
    assert journal.step_status("r1", "s") == "started"
    assert journal.run_step("r1", "s", "read", "GET x", lambda: "ok", digest=_ident).status == "ran"


@pytest.mark.parametrize("failure", [ValueError("boom"), Crash()])
def test_unfinished_write_needs_reconcile_and_never_reruns(
    journal: SqliteJournal, failure: BaseException
) -> None:
    def fail() -> str:
        raise failure

    with pytest.raises(type(failure)):
        journal.run_step("r1", "w", "write", "PUT x", fail, digest=_ident)

    calls: list[int] = []

    def body() -> str:
        calls.append(1)
        return "v"

    for _ in range(2):
        with pytest.raises(NeedsReconcileError) as info:
            journal.run_step("r1", "w", "write", "PUT x", body, digest=_ident)
        assert info.value.step_key == "w"
    assert calls == []
    assert journal.step_status("r1", "w") == "needs_reconcile"
    statuses = [
        r[0]
        for r in sqlite3.connect(journal.path)
        .execute("SELECT status FROM step_events WHERE step_key = 'w' ORDER BY id")
        .fetchall()
    ]
    # Only one needs_reconcile event, however often the step is re-attempted.
    assert statuses.count("needs_reconcile") == 1


def test_step_key_reuse_with_different_request_conflicts(journal: SqliteJournal) -> None:
    journal.run_step("r1", "s", "read", "GET x", lambda: "v", digest=_ident)
    with pytest.raises(StepConflictError):
        journal.run_step("r1", "s", "read", "GET y", lambda: "v", digest=_ident)
    with pytest.raises(StepConflictError):
        journal.run_step("r1", "s", "write", "GET x", lambda: "v", digest=_ident)


def test_steps_require_a_run(tmp_path: Path) -> None:
    with SqliteJournal(tmp_path / "j.sqlite") as j, pytest.raises(sqlite3.IntegrityError):
        j.run_step("nope", "s", "read", "GET x", lambda: "v", digest=_ident)


def test_timestamps_are_utc_z(tmp_path: Path) -> None:
    plus2 = datetime(2026, 11, 25, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    with SqliteJournal(tmp_path / "j.sqlite", now=lambda: plus2) as j:
        j.begin_run("r1", "scout", "LIVE")
        j.record_decision(
            GateRecord("r1", 1, "scout", "op", "t", "ten", None, None, "denied", "x", "", plus2)
        )
    conn = sqlite3.connect(tmp_path / "j.sqlite")
    try:
        assert conn.execute("SELECT started_at FROM runs").fetchone()[0] == "2026-11-25T12:00:00Z"
        assert conn.execute("SELECT at FROM gate_decisions").fetchone()[0] == "2026-11-25T12:00:00Z"
    finally:
        conn.close()


def test_data_survives_reopen_and_counts_decisions(tmp_path: Path) -> None:
    path = tmp_path / "j.sqlite"
    with SqliteJournal(path, now=lambda: T0) as j:
        j.begin_run("r1", "scout", "FIXTURE")
        for seq, decision in enumerate(["allowed", "allowed", "denied"], 1):
            j.record_decision(
                GateRecord("r1", seq, "scout", "op", "t", "ten", None, None, decision, None, "", T0)  # type: ignore[arg-type]
            )
    with SqliteJournal(path) as j:
        assert j.has_run("r1")
        assert j.decision_counts("r1") == {"allowed": 2, "denied": 1}
        assert j.decision_counts("other") == {"allowed": 0, "denied": 0}


def test_file_can_be_deleted_after_close(tmp_path: Path) -> None:
    """Windows keeps files locked while a connection is open."""
    path = tmp_path / "j.sqlite"
    j = SqliteJournal(path)
    j.begin_run("r1", "scout", "LIVE")
    j.close()
    path.unlink()
    assert not path.exists()


# --- stateful: random sequences of runs, failures, crashes and resumes ------------------


class JournalMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.tmp: Path | None = None
        self.journal: SqliteJournal | None = None
        self.executions: dict[str, int] = {}
        self.succeeded: set[str] = set()
        self.unfinished_writes: set[str] = set()

    @initialize(tmp=st.just(None))
    def open(self, tmp: None) -> None:
        import tempfile

        self._dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._dir.name)
        self.journal = SqliteJournal(self.tmp / "j.sqlite", now=lambda: T0)
        self.journal.begin_run("r", "strike", "FIXTURE")

    @rule(
        key=st.sampled_from(["a", "b", "c"]),
        kind=st.sampled_from(["read", "write"]),
        outcome=st.sampled_from(["ok", "error", "crash"]),
    )
    def attempt(self, key: str, kind: str, outcome: str) -> None:
        assert self.journal is not None
        step = f"{kind}-{key}"

        def body() -> str:
            self.executions[step] = self.executions.get(step, 0) + 1
            if outcome == "error":
                raise ValueError("boom")
            if outcome == "crash":
                raise Crash
            return step

        try:
            result = self.journal.run_step("r", step, kind, f"req {step}", body, digest=_ident)  # type: ignore[arg-type]
        except NeedsReconcileError:
            assert step in self.unfinished_writes
            return
        except (ValueError, Crash):
            if kind == "write":
                self.unfinished_writes.add(step)
            return
        if result.status == "ran":
            self.succeeded.add(step)
        else:
            assert step in self.succeeded

    @precondition(lambda self: self.journal is not None)
    @rule()
    def reopen(self) -> None:
        assert self.journal is not None and self.tmp is not None
        self.journal.close()
        self.journal = SqliteJournal(self.tmp / "j.sqlite", now=lambda: T0)

    @invariant()
    def writes_execute_at_most_once(self) -> None:
        for step, n in self.executions.items():
            if step.startswith("write-"):
                assert n <= 1, step

    @invariant()
    def unfinished_writes_never_report_success(self) -> None:
        if self.journal is None:
            return
        for step in self.unfinished_writes:
            assert self.journal.step_status("r", step) in {"started", "failed", "needs_reconcile"}
            assert step not in self.succeeded

    def teardown(self) -> None:
        if self.journal is not None:
            self.journal.close()
            self._dir.cleanup()


JournalMachine.TestCase.settings = settings(max_examples=30, stateful_step_count=15, deadline=None)
test_journal_state_machine = JournalMachine.TestCase


def test_strike_events_round_trip_in_order(journal: SqliteJournal) -> None:
    journal.strike_event("r1", "S3/add-password", "intent", {"url": "u", "b": 1})
    journal.strike_event(
        "r1", "S3/add-password", "result", {"status": 200, "learned": {"keyId": "k"}}
    )
    journal.strike_event("r2", "S1/list-keys", "intent", {})
    assert journal.strike_events("r1") == [
        ("S3/add-password", "intent", {"b": 1, "url": "u"}),
        ("S3/add-password", "result", {"learned": {"keyId": "k"}, "status": 200}),
    ]


def test_strike_event_phase_is_checked(journal: SqliteJournal) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        journal.strike_event("r1", "k", "rewrite", {})  # type: ignore[arg-type]
