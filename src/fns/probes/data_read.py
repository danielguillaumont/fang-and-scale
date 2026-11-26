"""Rung 3: a non-destructive data-plane read as the test identity (interface only).

The scope gate cannot name data-plane reads yet (``arm:`` and ``graph:`` only),
so a live data read has no gated path and is refused. Adding that vocabulary is
M3 P5.1 and needs review (docs/milestones/M3.md, decision E3).
"""

from __future__ import annotations

from typing import Literal

from fns.models.assertions import ProbeObservation, ProbeSpec
from fns.probes.base import Probe, ProbeUnavailableError


class DataReadProbe:
    mode: Literal["LIVE", "FIXTURE"] = "LIVE"

    def observe(self, spec: ProbeSpec, finding_id: str) -> ProbeObservation:
        raise ProbeUnavailableError(
            "live data-plane reads need a scope-gate vocabulary for them (M3 P5.1)"
        )


class RoutedProbe:
    """Send each spec to the probe registered for its kind."""

    def __init__(self, by_kind: dict[str, Probe], *, mode: Literal["LIVE", "FIXTURE"]) -> None:
        self._by_kind = by_kind
        self.mode: Literal["LIVE", "FIXTURE"] = mode

    def observe(self, spec: ProbeSpec, finding_id: str) -> ProbeObservation:
        probe = self._by_kind.get(spec.kind)
        if probe is None:
            raise ProbeUnavailableError(f"no probe for {spec.kind}")
        return probe.observe(spec, finding_id)
