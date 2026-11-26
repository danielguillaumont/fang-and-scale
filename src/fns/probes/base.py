"""The probe interface and what every probe returns."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol

from fns.models.assertions import ProbeObservation, ProbeSpec
from fns.models.evidence import Outcome


class ProbeUnavailableError(RuntimeError):
    """This probe kind cannot run here (no gate vocabulary, no credential, offline)."""


class Probe(Protocol):
    mode: Literal["LIVE", "FIXTURE"]

    def observe(self, spec: ProbeSpec, finding_id: str) -> ProbeObservation:
        """Run one probe. Raise :class:`ProbeUnavailableError` if it cannot run."""
        ...


def observation(
    spec: ProbeSpec,
    finding_id: str,
    *,
    mode: Literal["LIVE", "FIXTURE"],
    outcome: Outcome,
    detail: str,
    at: datetime,
    http_status: int | None = None,
    request_id: str | None = None,
) -> ProbeObservation:
    return ProbeObservation(
        version=1,
        mode=mode,
        probe_id=spec.id,
        finding_id=finding_id,
        kind=spec.kind,
        rung=spec.rung,
        outcome=outcome,
        detail=detail,
        http_status=http_status,
        request_id=request_id,
        observed_at=at,
    )
