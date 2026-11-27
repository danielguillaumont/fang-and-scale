"""Read a run directory and prove it was not tampered with, or refuse it.

The verifier reads exactly three things (PLAN §6, docs/milestones/M3.md):

- ``assertions.json``: frozen assertions; its sha256 must equal the digest of the
  journal's ``freeze-assertions`` step;
- ``journal.sqlite``: opened read-only (``mode=ro``) with the stdlib, never through
  the journal writer; the freeze must precede every probe event;
- ``artifacts/<sha256>.json``: each probe step's artifact, re-hashed.

Anything unexpected raises :class:`IntegrityError`. Nothing here repairs input.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from fns.inputcap import MAX_RECORD_BYTES, InputTooLargeError, read_capped
from fns.models.assertions import AssertionSet, ProbeObservation, StrikeObservation

ASSERTIONS_FILE: Final = "assertions.json"
JOURNAL_FILE: Final = "journal.sqlite"
ARTIFACTS_DIR: Final = "artifacts"
FREEZE_STEP: Final = "freeze-assertions"
PROBE_PREFIX: Final = "probe:"
STRIKE_PREFIX: Final = "strike:"


class IntegrityError(RuntimeError):
    """The run directory does not prove what it claims; no bundle is produced."""


@dataclass(frozen=True, slots=True)
class Inputs:
    run_dir: Path
    assertions: AssertionSet
    assertions_digest: str
    observations: dict[str, tuple[ProbeObservation, str]]
    """probe id -> (observation, artifact sha256), for probe steps that succeeded."""
    unfinished: tuple[str, ...]
    """Probe ids whose step failed or never finished: no evidence."""
    strikes: tuple[tuple[StrikeObservation, str], ...] = ()
    """After-harden strike observations (D6) and their artifact sha256, by step key."""


def open_read_only(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise IntegrityError(f"no journal at {path.name}")
    uri = path.resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_inputs(run_dir: Path) -> Inputs:
    raw = read_file(run_dir / ASSERTIONS_FILE)
    digest = _sha256(raw)
    try:
        aset = AssertionSet.model_validate_json(raw)
    except ValidationError as exc:
        raise IntegrityError(f"assertions.json is invalid: {exc.error_count()} error(s)") from exc
    if aset.file_bytes() != raw:
        raise IntegrityError("assertions.json is not in canonical form")

    conn = open_read_only(run_dir / JOURNAL_FILE)
    try:
        run = conn.execute(
            "SELECT verb, mode FROM runs WHERE run_id = ?", (aset.run_id,)
        ).fetchone()
        if run is None:
            raise IntegrityError("the journal has no record of this run")
        if run[1] != aset.mode:
            raise IntegrityError("journal mode differs from the assertions")
        events = conn.execute(
            "SELECT id, step_key, status, response_digest FROM step_events "
            "WHERE run_id = ? ORDER BY id",
            (aset.run_id,),
        ).fetchall()
    finally:
        conn.close()

    freeze = [e for e in events if e[1] == FREEZE_STEP]
    frozen = [e for e in freeze if e[2] == "succeeded"]
    if not frozen:
        raise IntegrityError("the assertions were never frozen in the journal")
    if frozen[-1][3] != digest:
        raise IntegrityError("assertions.json differs from the digest frozen in the journal")
    first_freeze = min(e[0] for e in freeze)
    frozen_at = frozen[0][0]

    last: dict[str, tuple[str, str | None]] = {}
    strike_last: dict[str, tuple[str, str | None]] = {}
    for event_id, key, status, response_digest in events:
        if key == FREEZE_STEP:
            continue
        if key.startswith(STRIKE_PREFIX):
            if event_id < frozen_at or event_id < first_freeze:
                raise IntegrityError("strike evidence was recorded before the freeze")
            strike_last[key] = (status, response_digest)
            continue
        if not key.startswith(PROBE_PREFIX):
            raise IntegrityError(f"unexpected journal step {key!r}")
        if event_id < frozen_at or event_id < first_freeze:
            raise IntegrityError("a probe ran before the assertions were frozen")
        pid = key.removeprefix(PROBE_PREFIX)
        if aset.probe(pid) is None:
            raise IntegrityError(f"journal names a probe that was not frozen: {pid[:12]}")
        last[pid] = (status, response_digest)

    observations: dict[str, tuple[ProbeObservation, str]] = {}
    unfinished: list[str] = []
    for pid, (status, response_digest) in sorted(last.items()):
        if status != "succeeded" or response_digest is None:
            unfinished.append(pid)
            continue
        observations[pid] = (_artifact(run_dir, aset, pid, response_digest), response_digest)
    strikes = tuple(
        (_strike_artifact(run_dir, aset, key, response_digest), response_digest)
        for key, (status, response_digest) in sorted(strike_last.items())
        if status == "succeeded" and response_digest is not None
    )
    return Inputs(run_dir, aset, digest, observations, tuple(unfinished), strikes)


def read_file(path: Path) -> bytes:
    """A run-directory file, capped (``fns.inputcap``); IntegrityError if unreadable."""
    try:
        return read_capped(path, MAX_RECORD_BYTES)
    except (OSError, InputTooLargeError) as exc:
        raise IntegrityError(f"cannot read {path.name}") from exc


def _artifact(run_dir: Path, aset: AssertionSet, pid: str, digest: str) -> ProbeObservation:
    data = read_file(run_dir / ARTIFACTS_DIR / f"{digest}.json")
    if _sha256(data) != digest:
        raise IntegrityError(f"artifact {digest[:12]} does not match its digest")
    try:
        obs = ProbeObservation.model_validate_json(data)
    except ValidationError as exc:
        raise IntegrityError(f"artifact {digest[:12]} is invalid") from exc
    found = aset.probe(pid)
    if found is None:
        raise IntegrityError(f"journal names a probe that was not frozen: {pid[:12]}")
    assertion, spec = found
    if (obs.probe_id, obs.finding_id) != (spec.id, assertion.finding_id):
        raise IntegrityError(f"artifact {digest[:12]} belongs to another probe")
    if (obs.kind, obs.rung) != (spec.kind, spec.rung):
        raise IntegrityError(f"artifact {digest[:12]} claims a different probe kind or rung")
    if obs.mode != aset.mode:
        raise IntegrityError(f"artifact {digest[:12]} has a different mode than the run")
    return obs


def _strike_artifact(run_dir: Path, aset: AssertionSet, key: str, digest: str) -> StrikeObservation:
    data = read_file(run_dir / ARTIFACTS_DIR / f"{digest}.json")
    if _sha256(data) != digest:
        raise IntegrityError(f"artifact {digest[:12]} does not match its digest")
    try:
        obs = StrikeObservation.model_validate_json(data)
    except ValidationError as exc:
        raise IntegrityError(f"strike artifact {digest[:12]} is invalid") from exc
    if obs.step_key != key:
        raise IntegrityError(f"strike artifact {digest[:12]} belongs to another step")
    if obs.mode != aset.mode:
        raise IntegrityError(f"strike artifact {digest[:12]} has a different mode than the run")
    return obs
