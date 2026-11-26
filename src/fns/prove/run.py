"""Orchestrate one ``fns prove`` run, then hand the run directory to the verifier.

Order (docs/milestones/M3.md): contain report -> freeze assertions (file + journal)
-> probes (journaled, content-addressed) -> close the journal -> start the
verifier as a separate process with a scrubbed environment. The orchestrator
never computes a verdict itself; the exit code is the verifier's.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Literal

from fns.contain_run import contain
from fns.journal.sqlite import SqliteJournal
from fns.models.assertions import AssertionSet
from fns.models.contract import Contract
from fns.models.report import ContainReport
from fns.models.snapshot import Snapshot
from fns.probes.base import Probe
from fns.probes.runner import ProbeRun, freeze_into, run_probes
from fns.prove.freeze import freeze

JOURNAL_FILE: Final = "journal.sqlite"
SCRUBBED_PREFIXES: Final = ("AZURE_", "ARM_", "MSI_", "IDENTITY_", "MSAL_")
SCRUBBED_NAMES: Final = frozenset({"GITHUB_TOKEN", "GH_TOKEN"})

Signer = Literal["offline-test", "sigstore", "none"]


def verifier_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """The verifier's environment: no executor or test-identity credentials (E7).

    The GitHub OIDC request variables stay: in CI they are how the verifier gets
    its *own* identity for Sigstore keyless signing.
    """
    source = os.environ if env is None else env
    return {
        k: v
        for k, v in source.items()
        if not k.upper().startswith(SCRUBBED_PREFIXES) and k.upper() not in SCRUBBED_NAMES
    }


@dataclass(frozen=True, slots=True)
class ProveResult:
    report: ContainReport
    assertions: AssertionSet
    run_dir: Path
    probes: ProbeRun
    exit_code: int
    output: str
    """The verifier process's stdout (and stderr, if any)."""


ProbeFactory = Callable[[SqliteJournal, str], Probe]
"""Builds the probe once the run journal is open: ``(journal, run_id) -> probe``.
Live probes need it, so their gate journals into the run's own journal."""


def prepare(
    contract: Contract,
    snapshot: Snapshot,
    probe: Probe | ProbeFactory,
    out_dir: Path,
    *,
    now: Callable[[], datetime],
) -> tuple[ContainReport, AssertionSet, Path, ProbeRun]:
    when = now()
    report = contain(contract, snapshot, now=when)
    aset = freeze(contract, snapshot, report, frozen_at=when)
    mode = getattr(probe, "mode", "LIVE")  # a factory builds a live probe
    if mode == "FIXTURE" and aset.mode != "FIXTURE":
        # Fixture probe results make the whole run FIXTURE evidence.
        aset = AssertionSet.model_validate({**aset.model_dump(), "mode": "FIXTURE"})
    run_dir = out_dir / "runs" / aset.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    with SqliteJournal(run_dir / JOURNAL_FILE, now=now) as journal:
        if not journal.has_run(aset.run_id):
            journal.begin_run(aset.run_id, "prove", aset.mode)
        freeze_into(journal, aset, run_dir)
        built = probe if hasattr(probe, "observe") else probe(journal, aset.run_id)
        probes = run_probes(journal, aset, built, run_dir, now=now)  # type: ignore[arg-type]
    return report, aset, run_dir, probes


def spawn_verifier(
    args: list[str], *, env: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv: this interpreter, our own module
        [sys.executable, "-m", "fns.verify", *args],
        env=verifier_env(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def prove(
    contract: Contract,
    snapshot: Snapshot,
    probe: Probe | ProbeFactory,
    out_dir: Path,
    *,
    now: Callable[[], datetime],
    signer: Signer = "offline-test",
    identity: str = "unspecified",
) -> ProveResult:
    report, aset, run_dir, probes = prepare(contract, snapshot, probe, out_dir, now=now)
    done = spawn_verifier(["run", "--run", str(run_dir), "--sign", signer, "--identity", identity])
    output = done.stdout + (done.stderr or "")
    return ProveResult(report, aset, run_dir, probes, done.returncode, output)


def check_run(run_dir: Path) -> tuple[int, str]:
    done = spawn_verifier(["check", "--run", str(run_dir)])
    return done.returncode, done.stdout + (done.stderr or "")
