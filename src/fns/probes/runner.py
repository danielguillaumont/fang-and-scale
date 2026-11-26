"""Run every frozen probe once, journal it, and store what it saw content-addressed.

Each probe is a journaled *read* step keyed ``probe:<probe id>``; its response
digest is the sha256 of the observation artifact written to
``<run>/artifacts/<sha256>.json``. A probe that cannot run is recorded as
outcome ``not-run`` (a succeeded step with a ``not-run`` artifact). A probe that
crashes leaves a ``failed`` step and no artifact: the verifier treats both as
"no evidence".
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from fns.journal.sqlite import SqliteJournal
from fns.models.assertions import AssertionSet, ProbeObservation, ProbeSpec
from fns.probes.base import Probe, ProbeUnavailableError, observation

FREEZE_STEP: Final = "freeze-assertions"
ASSERTIONS_FILE: Final = "assertions.json"
ARTIFACTS_DIR: Final = "artifacts"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_artifact(run_dir: Path, data: bytes) -> str:
    digest = sha256_bytes(data)
    path = run_dir / ARTIFACTS_DIR / f"{digest}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(data)
    return digest


def freeze_into(journal: SqliteJournal, aset: AssertionSet, run_dir: Path) -> str:
    """Write ``assertions.json`` and journal its digest; must precede every probe."""
    data = aset.file_bytes()
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / ASSERTIONS_FILE).write_bytes(data)
    digest = sha256_bytes(data)
    journal.run_step(
        aset.run_id,
        FREEZE_STEP,
        "read",
        f"assertions {digest}",
        lambda: digest,
        digest=lambda d: d,
    )
    return digest


@dataclass(frozen=True, slots=True)
class ProbeRun:
    observations: tuple[ProbeObservation, ...]
    failed: tuple[str, ...]
    """Probe ids whose step failed (no artifact)."""


def run_probes(
    journal: SqliteJournal,
    aset: AssertionSet,
    probe: Probe,
    run_dir: Path,
    *,
    now: Callable[[], datetime],
) -> ProbeRun:
    if journal.step_status(aset.run_id, FREEZE_STEP) != "succeeded":
        raise RuntimeError("assertions must be frozen before any probe runs")
    observations: list[ProbeObservation] = []
    failed: list[str] = []
    for a in aset.assertions:
        for spec in a.probes:

            def body(s: ProbeSpec = spec, finding_id: str = a.finding_id) -> ProbeObservation:
                try:
                    obs = probe.observe(s, finding_id)
                except ProbeUnavailableError as exc:
                    obs = observation(
                        s, finding_id, mode=probe.mode, outcome="not-run", detail=str(exc), at=now()
                    )
                if obs.probe_id != s.id or obs.finding_id != finding_id:
                    raise ValueError("probe returned an observation for another probe")
                write_artifact(run_dir, obs.file_bytes())
                return obs

            try:
                result = journal.run_step(
                    aset.run_id,
                    f"probe:{spec.id}",
                    "read",
                    f"{spec.kind} {spec.action} on {spec.target}",
                    body,
                    digest=lambda o: sha256_bytes(o.file_bytes()),
                )
            except Exception:  # noqa: BLE001 - a crashing probe is "no evidence", not a stop
                failed.append(spec.id)
                continue
            if result.value is not None:
                observations.append(result.value)
    return ProbeRun(tuple(observations), tuple(failed))
