"""What ``fns strike run`` and ``fns strike cleanup`` write: ``strike-run.json``, ``cleanup.json``.

Read back by ``fns prove --after-strike`` and ``fns report --strike``. The strike
engine writes it from ``StrikeRun.to_dict`` (``fns.strike.run``); this model is
the reading side, kept out of the engine so readers never import it. A test
round-trips the engine's output through this model.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from fns.models.base import FnsModel

StrikeOutcome = Literal[
    "succeeded", "denied", "unexpected-success", "failed", "gate-denied", "unknown", "not-run"
]


class StrikeWriteRecord(FnsModel):
    key: str = Field(pattern=r"^(S[1-4]|D-[1-9])/[a-z0-9-]+$")
    strike: str = Field(pattern=r"^(S[1-4]|D-[1-9])$")
    expect: Literal["allowed", "denied"]
    outcome: StrikeOutcome
    status: int | None = None
    undo: tuple[str, ...] = ()
    """The status of each undo request sent, in order (empty: nothing to undo)."""
    observes: tuple[str, ...] = ()


class StrikeCheckRecord(FnsModel):
    what: str = Field(min_length=1)
    ok: bool
    detail: str


class StrikeRunRecord(FnsModel):
    mode: Literal["LIVE", "FIXTURE"]
    run_id: str = Field(pattern=r"^[a-z0-9-]{8,40}$")
    plan_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    aborted: str | None = None
    writes: tuple[StrikeWriteRecord, ...]
    verification: tuple[StrikeCheckRecord, ...] = ()
    exit_code: Literal[0, 1, 4, 5]
    journal: str | None = None
    """Where the run's journal was written (a local path; not shown in reports)."""

    @property
    def strikes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(w.strike for w in self.writes))

    @property
    def verified(self) -> bool:
        return all(c.ok for c in self.verification)
