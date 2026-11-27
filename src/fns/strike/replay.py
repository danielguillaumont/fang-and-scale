"""Recorded strike runs, replayed (FIXTURE): ``fns strike ... --fixture DIR``.

A recording directory holds ``scope.yaml`` (placeholder IDs) and one JSON file
per scenario (``before-harden.json``, ``after-harden.json``). Each recording has
the run's fixed time and run ID, the scout's reads in order, and the agent's
writes in order. Every body was stripped of secrets before it was written.

Replay is strict:

- each write must be the next recorded one: same method, URL and body sha256,
  or the replay stops with a transport error (and the runner undoes what it
  can, as it would live);
- reads are matched by URL, in the order they were recorded, separately for
  ``plan`` and ``run``; after the last recorded answer for a URL, that answer
  is repeated. ``cleanup`` sees the lab as the run left it (the last answers);
- nothing leaves the process: no token, no socket.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import Field

from fns.adapters.azure.http import ApiRequest, ApiResponse, TransportError
from fns.models.base import FnsModel, sha256_hex
from fns.models.ids import TzDatetime
from fns.scope.writes import canonical_body
from fns.strike.plan import StrikeId
from fns.strike.secrets import strip_secrets
from fns.strike.transport import StrikeRequest, StrikeTransport

SCOPE_FILE: Final = "scope.yaml"
SCENARIOS: Final[tuple[str, ...]] = ("before-harden", "after-harden")


class RecordedRead(FnsModel):
    url: str
    status: int
    body: dict[str, Any]


class RecordedWrite(FnsModel):
    method: Literal["POST", "PATCH", "DELETE"]
    url: str
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: int
    body: dict[str, Any]
    request_id: str | None = None


class StrikeRecording(FnsModel):
    version: Literal[1] = 1
    mode: Literal["FIXTURE"] = "FIXTURE"
    description: str
    now: TzDatetime
    run_id: str
    strikes: tuple[StrikeId, ...]
    agent_object_id: str
    scout_object_id: str
    plan_reads: tuple[RecordedRead, ...]
    """The scout's reads during ``fns strike plan``."""
    reads: tuple[RecordedRead, ...]
    """The scout's reads during ``fns strike run``."""
    writes: tuple[RecordedWrite, ...]


class ReplayError(TransportError):
    """The run asked for something the recording does not have."""


def load_recording(directory: Path, scenario: str) -> StrikeRecording:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; one of {', '.join(SCENARIOS)}")
    return StrikeRecording.model_validate_json((directory / f"{scenario}.json").read_bytes())


def body_sha256(body: object) -> str:
    return sha256_hex(canonical_body(body))


class ReplayWrites(StrikeTransport):
    def __init__(self, recording: StrikeRecording) -> None:
        self._writes = deque(recording.writes)

    def _exchange(self, request: StrikeRequest) -> tuple[int, object, str | None]:
        if not self._writes:
            raise ReplayError("replay: the recording has no more writes")
        w = self._writes.popleft()
        same = (w.method, w.url, w.body_sha256) == (
            request.method,
            request.url,
            body_sha256(request.body),
        )
        if not same:
            raise ReplayError(f"replay: {request.method} {request.url} differs from the recording")
        return w.status, w.body, w.request_id

    @property
    def remaining(self) -> int:
        return len(self._writes)


class ReplayReads:
    """The scout's read transport, from the recording."""

    def __init__(self, recording: StrikeRecording, phase: Literal["plan", "run", "after"]) -> None:
        """``after`` (cleanup): the lab as the run left it, the last answer per URL."""
        self._by_url: dict[str, deque[RecordedRead]] = defaultdict(deque)
        for r in recording.plan_reads if phase == "plan" else recording.reads:
            self._by_url[r.url].append(r)
        if phase == "after":
            self._by_url = defaultdict(deque, {u: deque([q[-1]]) for u, q in self._by_url.items()})
        self._last: dict[str, RecordedRead] = {}

    def fetch(self, request: ApiRequest) -> ApiResponse:
        queue = self._by_url.get(request.url)
        if queue:
            self._last[request.url] = queue.popleft()
        found = self._last.get(request.url)
        if found is None:
            raise ReplayError(f"replay: no recorded read of {request.url}")
        return ApiResponse(found.status, json.loads(json.dumps(found.body)), "recorded")


# --- making a recording (tests and the fixture generator) ----------------------------


@dataclass
class Recorder:
    """Wraps a read transport and a write transport; keeps stripped exchanges."""

    plan_reads: list[RecordedRead] = field(default_factory=list)
    reads: list[RecordedRead] = field(default_factory=list)
    writes: list[RecordedWrite] = field(default_factory=list)
    phase: Literal["plan", "run"] = "plan"

    def read(self, request: ApiRequest, response: ApiResponse) -> ApiResponse:
        clean, _ = strip_secrets(response.body)
        (self.plan_reads if self.phase == "plan" else self.reads).append(
            RecordedRead(url=request.url, status=response.status, body=clean)
        )
        return response

    def write(
        self, request: StrikeRequest, status: int, raw: object, request_id: str | None
    ) -> None:
        clean, _ = strip_secrets(raw)
        self.writes.append(
            RecordedWrite(
                method=request.method,  # type: ignore[arg-type]
                url=request.url,
                body_sha256=body_sha256(request.body),
                status=status,
                body=clean if isinstance(clean, dict) else {},
                request_id=request_id,
            )
        )

    def recording(
        self,
        *,
        description: str,
        now: datetime,
        run_id: str,
        strikes: tuple[StrikeId, ...],
        agent: str,
        scout: str,
    ) -> StrikeRecording:
        return StrikeRecording(
            description=description,
            now=now,
            run_id=run_id,
            strikes=strikes,
            agent_object_id=agent,
            scout_object_id=scout,
            plan_reads=tuple(self.plan_reads),
            reads=tuple(self.reads),
            writes=tuple(self.writes),
        )


def recording_json(recording: StrikeRecording) -> str:
    data: Mapping[str, Any] = json.loads(recording.canonical_json())
    return json.dumps(data, indent=2, sort_keys=True) + "\n"
