"""Append-only SQLite run journal.

Every table is append-only: ``BEFORE UPDATE`` / ``BEFORE DELETE`` triggers
abort. A step's status is its latest event.

Step semantics (:meth:`SqliteJournal.run_step`):

- ``succeeded`` before: skipped, the recorded response digest is returned.
- never run, or a *read* that previously failed / never finished: run it.
- a *write* that previously failed or never finished (crash): never re-run
  automatically; a ``needs_reconcile`` event is appended and
  :class:`NeedsReconcileError` raised. A crash is never counted as a pass.

An ordinary exception from the step body records ``failed``. A
``BaseException`` that is not an ``Exception`` (KeyboardInterrupt, a killed
process) records nothing, leaving the step ``started``, i.e. unknown.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Final, Literal, TypeVar

from fns.models.ids import utc_isoformat
from fns.scope.gate import GateRecord

T = TypeVar("T")
StepKind = Literal["read", "write"]
StepStatus = Literal["started", "succeeded", "failed", "needs_reconcile"]

_TABLES: Final = (
    "runs",
    "steps",
    "step_events",
    "gate_decisions",
    "gate_results",
    "strike_events",
)
StrikePhase = Literal[
    "intent", "result", "error", "undo-intent", "undo-result", "undo-error", "verify"
]

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    verb        TEXT NOT NULL,
    mode        TEXT NOT NULL CHECK (mode IN ('LIVE', 'FIXTURE')),
    started_at  TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS steps (
    run_id          TEXT NOT NULL REFERENCES runs(run_id),
    step_key        TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('read', 'write')),
    request_summary TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (run_id, step_key)
) STRICT;
CREATE TABLE IF NOT EXISTS step_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    step_key        TEXT NOT NULL,
    status          TEXT NOT NULL
                    CHECK (status IN ('started', 'succeeded', 'failed', 'needs_reconcile')),
    at              TEXT NOT NULL,
    response_digest TEXT,
    detail          TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (run_id, step_key) REFERENCES steps(run_id, step_key)
) STRICT;
CREATE TABLE IF NOT EXISTS gate_decisions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    verb         TEXT NOT NULL,
    operation    TEXT NOT NULL,
    target       TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    principal_id TEXT,
    url          TEXT,
    decision     TEXT NOT NULL CHECK (decision IN ('allowed', 'denied')),
    reason       TEXT,
    detail       TEXT NOT NULL,
    at           TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS strike_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    TEXT NOT NULL,
    write_key TEXT NOT NULL,
    phase     TEXT NOT NULL CHECK (phase IN ('intent', 'result', 'error', 'undo-intent',
                                             'undo-result', 'undo-error', 'verify')),
    detail    TEXT NOT NULL,
    at        TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS gate_results (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  TEXT NOT NULL,
    seq     INTEGER NOT NULL,
    status  TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
    detail  TEXT NOT NULL,
    at      TEXT NOT NULL
) STRICT;
"""


def _append_only_triggers() -> str:
    out = []
    for table in _TABLES:
        for action in ("UPDATE", "DELETE"):
            out.append(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} "
                f"BEFORE {action} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;"
            )
    return "\n".join(out)


class JournalError(RuntimeError):
    pass


class NeedsReconcileError(JournalError):
    """A write step did not finish cleanly; a human or cleanup must reconcile it."""

    def __init__(self, run_id: str, step_key: str) -> None:
        super().__init__(f"write step {step_key!r} in run {run_id} needs reconciliation")
        self.run_id = run_id
        self.step_key = step_key


class StepConflictError(JournalError):
    """A step key was reused for a different kind or request."""


@dataclass(frozen=True, slots=True)
class StepResult[T]:
    status: Literal["ran", "skipped"]
    value: T | None
    response_digest: str | None


@dataclass(frozen=True, slots=True)
class StepRow:
    step_key: str
    kind: StepKind
    status: StepStatus


class SqliteJournal:
    """One connection per journal object. Always close it (Windows file locks)."""

    def __init__(self, path: Path, *, now: Callable[[], datetime] | None = None) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._now = now or (lambda: datetime.now(UTC))
        self._conn = sqlite3.connect(path, isolation_level=None)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA synchronous = FULL")
        self._conn.executescript(_SCHEMA + _append_only_triggers())

    # -- lifecycle -------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SqliteJournal:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _ts(self, at: datetime | None = None) -> str:
        return utc_isoformat(at or self._now())

    def _write(self, sql: str, params: tuple[object, ...]) -> None:
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(sql, params)

    # -- runs ----------------------------------------------------------------------------

    def begin_run(self, run_id: str, verb: str, mode: Literal["LIVE", "FIXTURE"]) -> None:
        self._write(
            "INSERT INTO runs (run_id, verb, mode, started_at) VALUES (?, ?, ?, ?)",
            (run_id, verb, mode, self._ts()),
        )

    def has_run(self, run_id: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return row is not None

    # -- steps ---------------------------------------------------------------------------

    def step_status(self, run_id: str, step_key: str) -> StepStatus | None:
        row = self._conn.execute(
            "SELECT status FROM step_events WHERE run_id = ? AND step_key = ? "
            "ORDER BY id DESC LIMIT 1",
            (run_id, step_key),
        ).fetchone()
        return None if row is None else row[0]

    def _last_digest(self, run_id: str, step_key: str) -> str | None:
        row = self._conn.execute(
            "SELECT response_digest FROM step_events WHERE run_id = ? AND step_key = ? "
            "AND status = 'succeeded' ORDER BY id DESC LIMIT 1",
            (run_id, step_key),
        ).fetchone()
        return None if row is None else row[0]

    def _event(
        self,
        run_id: str,
        key: str,
        status: StepStatus,
        digest: str | None = None,
        detail: str = "",
    ) -> None:
        self._write(
            "INSERT INTO step_events (run_id, step_key, status, at, response_digest, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, key, status, self._ts(), digest, detail),
        )

    def _ensure_step(self, run_id: str, key: str, kind: StepKind, summary: str) -> None:
        row = self._conn.execute(
            "SELECT kind, request_summary FROM steps WHERE run_id = ? AND step_key = ?",
            (run_id, key),
        ).fetchone()
        if row is None:
            self._write(
                "INSERT INTO steps (run_id, step_key, kind, request_summary, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (run_id, key, kind, summary, self._ts()),
            )
        elif tuple(row) != (kind, summary):
            raise StepConflictError(f"step {key!r} already recorded with a different request")

    def run_step(
        self,
        run_id: str,
        step_key: str,
        kind: StepKind,
        request_summary: str,
        fn: Callable[[], T],
        *,
        digest: Callable[[T], str],
    ) -> StepResult[T]:
        """Run ``fn`` at most once per (run, key) for writes; see module docstring."""
        self._ensure_step(run_id, step_key, kind, request_summary)
        status = self.step_status(run_id, step_key)
        if status == "succeeded":
            return StepResult("skipped", None, self._last_digest(run_id, step_key))
        if kind == "write" and status is not None:
            if status != "needs_reconcile":
                self._event(run_id, step_key, "needs_reconcile", detail=f"previous: {status}")
            raise NeedsReconcileError(run_id, step_key)

        self._event(run_id, step_key, "started")
        try:
            value = fn()
        except Exception as exc:
            self._event(run_id, step_key, "failed", detail=type(exc).__name__)
            raise
        d = digest(value)
        self._event(run_id, step_key, "succeeded", digest=d)
        return StepResult("ran", value, d)

    def steps(self, run_id: str) -> list[StepRow]:
        rows = self._conn.execute(
            "SELECT s.step_key, s.kind, "
            " (SELECT status FROM step_events e WHERE e.run_id = s.run_id AND "
            "  e.step_key = s.step_key ORDER BY id DESC LIMIT 1) "
            "FROM steps s WHERE s.run_id = ? ORDER BY s.step_key",
            (run_id,),
        ).fetchall()
        return [StepRow(k, kind, st) for k, kind, st in rows]

    # -- gate sink ---------------------------------------------------------------------

    def record_decision(self, record: GateRecord) -> None:
        self._write(
            "INSERT INTO gate_decisions (run_id, seq, verb, operation, target, tenant_id, "
            "principal_id, url, decision, reason, detail, at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.run_id,
                record.seq,
                record.verb,
                record.operation,
                record.target,
                record.tenant_id,
                record.principal_id,
                record.url,
                record.decision,
                record.reason,
                record.detail,
                self._ts(record.at),
            ),
        )

    def record_call_result(
        self,
        run_id: str,
        seq: int,
        status: Literal["succeeded", "failed"],
        detail: str,
        at: datetime,
    ) -> None:
        self._write(
            "INSERT INTO gate_results (run_id, seq, status, detail, at) VALUES (?, ?, ?, ?, ?)",
            (run_id, seq, status, detail, self._ts(at)),
        )

    # -- strikes (M4) ------------------------------------------------------------------

    def strike_event(
        self, run_id: str, write_key: str, phase: StrikePhase, detail: dict[str, object]
    ) -> None:
        """One strike journal row. ``detail`` holds IDs and digests, never a secret
        (the transport strips them before any caller sees the response)."""
        self._write(
            "INSERT INTO strike_events (run_id, write_key, phase, detail, at) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_id, write_key, phase, json.dumps(detail, sort_keys=True), self._ts()),
        )

    def strike_events(self, run_id: str) -> list[tuple[str, StrikePhase, dict[str, object]]]:
        rows = self._conn.execute(
            "SELECT write_key, phase, detail FROM strike_events WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
        return [(k, ph, json.loads(d)) for k, ph, d in rows]

    def decision_counts(self, run_id: str) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT decision, COUNT(*) FROM gate_decisions WHERE run_id = ? GROUP BY decision",
            (run_id,),
        ).fetchall()
        return {"allowed": 0, "denied": 0} | dict(rows)
