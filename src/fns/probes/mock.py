"""Replay recorded or hand-written probe results (FIXTURE).

File format (``probes.json``)::

    {"format": 1, "label": "FIXTURE", "source": "hand-written", "description": "...",
     "results": [{"kind": "data-read", "resource": "kv-crown-jewels",
                  "action": "secrets/get", "outcome": "denied",
                  "http_status": 403, "detail": "..."}]}

``source`` says where the results came from: ``recorded-live`` for a file written
by ``fns prove --live --record``, ``hand-written`` (the default) for anything
else. Replay banners say which; a file without the field never claims more than
hand-written.

``resource`` is the last segment of the probe target's ARM ID. A probe with no
recorded result raises :class:`ProbeUnavailableError` (outcome ``not-run``);
replay never invents a result.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from fns.inputcap import MAX_RECORD_BYTES, read_capped
from fns.models.assertions import ProbeKind, ProbeObservation, ProbeSpec
from fns.models.base import FnsModel
from fns.probes.base import ProbeUnavailableError, observation

RESULTS_FILE = "probes.json"
RECORDED_PREFIX = "Recorded from the lab by fns prove --live"
ResultsSource = Literal["hand-written", "recorded-live"]


class MockResult(FnsModel):
    kind: ProbeKind
    resource: str = Field(min_length=1)
    action: str = Field(min_length=1)
    outcome: Literal["allowed", "denied"]
    http_status: int | None = None
    detail: str = ""


class MockResults(FnsModel):
    format: Literal[1]
    label: Literal["FIXTURE"]
    source: ResultsSource = "hand-written"
    description: str = ""
    results: tuple[MockResult, ...]

    @model_validator(mode="after")
    def _recorded_says_so(self) -> MockResults:
        if self.source == "recorded-live" and not self.description.startswith(RECORDED_PREFIX):
            raise ValueError(
                f"source recorded-live needs a description starting {RECORDED_PREFIX!r}"
            )
        return self

    @property
    def provenance(self) -> str:
        """For banners: what a replay of these results is replaying."""
        if self.source == "recorded-live":
            return "recorded live probe results"
        return "hand-written probe results"


def load_results(path: Path) -> MockResults:
    return MockResults.model_validate_json(read_capped(path, MAX_RECORD_BYTES))


class MockProbe:
    mode: Literal["LIVE", "FIXTURE"] = "FIXTURE"

    def __init__(self, results: MockResults, *, at: datetime) -> None:
        self._at = at
        self._by_key: dict[tuple[str, str, str], MockResult] = {}
        for r in results.results:
            key = (r.kind, r.resource.lower(), r.action.lower())
            if key in self._by_key:
                raise ValueError(f"duplicate mock result {key}")
            self._by_key[key] = r
        self.used: set[tuple[str, str, str]] = set()

    def observe(self, spec: ProbeSpec, finding_id: str) -> ProbeObservation:
        key = (spec.kind, spec.target.rsplit("/", 1)[-1].lower(), spec.action.lower())
        r = self._by_key.get(key)
        if r is None:
            raise ProbeUnavailableError("no recorded result for this probe")
        self.used.add(key)
        return observation(
            spec,
            finding_id,
            mode="FIXTURE",
            outcome=r.outcome,
            detail=r.detail or f"recorded {r.outcome}",
            at=self._at,
            http_status=r.http_status,
        )
