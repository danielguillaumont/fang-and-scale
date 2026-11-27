"""Detection results per strike (M4 K5, decision D5): did each rule fire, and how fast.

D5: the operator runs one KQL query per strike and pastes the result
(``docs/runbooks/m4-live-run.md``, step C6). This file is that result, written
down: per strike, the rule that should fire, how many source rows arrived, and
whether and when the alert came.

It is **reported by the operator**, not queried or checked by the tool, so it is
shown in the report as such and never becomes evidence for a finding. It cannot
change a verdict, coverage or exit code.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Literal

from pydantic import Field, NonNegativeInt, model_validator

from fns.models.base import FnsModel
from fns.models.ids import TzDatetime

DetectionState = Literal["fired", "detection-gap", "no-rows"]


class DetectionResult(FnsModel):
    strike: str = Field(pattern=r"^(S[1-4]|D-[1-9])$")
    rule: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$", max_length=80)
    """A rule ID from ``detections/`` (its file name without ``.yaml``)."""
    strike_at: TzDatetime
    rows: NonNegativeInt
    """Source rows the strike's query returned (its event reached the workspace)."""
    fired: bool
    first_alert_at: TzDatetime | None = None
    note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _alert_time_matches(self) -> DetectionResult:
        if self.fired and self.first_alert_at is None:
            raise ValueError("a fired rule needs first_alert_at")
        if not self.fired and self.first_alert_at is not None:
            raise ValueError("first_alert_at is set but fired is false")
        if self.first_alert_at is not None and self.first_alert_at < self.strike_at:
            raise ValueError("the alert came before the strike")
        return self

    @property
    def state(self) -> DetectionState:
        if self.fired:
            return "fired"
        return "detection-gap" if self.rows else "no-rows"

    @property
    def latency(self) -> timedelta | None:
        return None if self.first_alert_at is None else self.first_alert_at - self.strike_at


class DetectionResults(FnsModel):
    version: Literal[1]
    mode: Literal["LIVE", "FIXTURE"]
    strike_run_id: str = Field(pattern=r"^[a-z0-9-]{8,40}$")
    """The ``fns strike run`` these results are for."""
    source: str = Field(min_length=1, max_length=500)
    """Who wrote it down and from what, e.g. the runbook step whose KQL was run."""
    results: tuple[DetectionResult, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _one_result_per_strike_and_rule(self) -> DetectionResults:
        keys = [(r.strike, r.rule) for r in self.results]
        if len(keys) != len(set(keys)):
            raise ValueError("a strike and rule pair is listed twice")
        return self
