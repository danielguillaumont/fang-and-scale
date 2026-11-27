"""CLI handlers for ``fns report`` and ``fns demo report`` (M5). Read-only: writes one HTML file."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from rich.console import Console

from fns.console import FixtureConsole
from fns.exitcodes import ExitCode
from fns.inputcap import MAX_RECORD_BYTES, read_capped
from fns.models.bundle import EvidenceBundle
from fns.models.detection_results import DetectionResults
from fns.models.mutation import MutationReport
from fns.models.report import ContainReport
from fns.models.strike_record import StrikeRunRecord
from fns.report.html import Inputs, ReportInputError, StrikeView, render_html
from fns.strike.plan import StrikePlan
from fns.yamlio import load_yaml

BUNDLE_FILE = "bundle.json"
SIGNING_FILE = "signing.json"
PLAN_FILE = "plan.json"
STRIKE_RUN_FILE = "strike-run.json"
CLEANUP_FILE = "cleanup.json"


def load_inputs(
    contain: Path,
    mutation: Path | None,
    prove_dir: Path | None,
    *,
    strikes: Sequence[Path] = (),
    detections: Path | None = None,
) -> Inputs:
    report = ContainReport.model_validate_json(read_capped(contain, MAX_RECORD_BYTES))
    mut = (
        MutationReport.model_validate_json(read_capped(mutation, MAX_RECORD_BYTES))
        if mutation
        else None
    )
    base = Inputs(report, mut, *load_inputs_bundle(prove_dir))
    return replace(
        base,
        strikes=tuple(load_strike(d) for d in strikes),
        detections=load_detections(detections) if detections else None,
    )


def load_strike(directory: Path) -> StrikeView:
    """A ``fns strike run`` directory: its plan, run record and any later cleanup."""
    plan = StrikePlan.model_validate_json(read_capped(directory / PLAN_FILE, MAX_RECORD_BYTES))
    run = StrikeRunRecord.model_validate_json(
        read_capped(directory / STRIKE_RUN_FILE, MAX_RECORD_BYTES)
    )
    cleanup_file = directory / CLEANUP_FILE
    cleanup = (
        StrikeRunRecord.model_validate_json(read_capped(cleanup_file, MAX_RECORD_BYTES))
        if cleanup_file.exists()
        else None
    )
    return StrikeView(plan, run, cleanup)


def load_detections(path: Path) -> DetectionResults:
    return DetectionResults.model_validate(load_yaml(path))


def load_inputs_from(
    report: ContainReport, mutation: MutationReport | None, prove_dir: Path | None
) -> Inputs:
    """Like :func:`load_inputs`, for reports already in memory (the demo)."""
    loaded = load_inputs_bundle(prove_dir)
    return Inputs(report, mutation, *loaded)


def load_inputs_bundle(
    prove_dir: Path | None,
) -> tuple[EvidenceBundle | None, dict[str, str] | None]:
    if prove_dir is None:
        return None, None
    bundle = EvidenceBundle.model_validate_json(
        read_capped(prove_dir / BUNDLE_FILE, MAX_RECORD_BYTES)
    )
    signing = None
    sig = prove_dir / SIGNING_FILE
    if sig.exists():
        raw = json.loads(read_capped(sig, MAX_RECORD_BYTES))
        signing = {k: str(v) for k, v in raw.items() if k in {"signer", "warning"}}
    return bundle, signing


def write(inputs: Inputs, out: Path, con: Console | FixtureConsole, err: Console) -> int:
    try:
        page = render_html(inputs)
    except ReportInputError as exc:
        err.print(f"refusing to mix runs: {exc}", style="fns.fail", markup=False)
        return int(ExitCode.INVALID_INPUT)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8", newline="\n")
    parts = ["contain"]
    if inputs.bundle:
        parts.append("prove")
    if inputs.strikes:
        parts.append(f"{len(inputs.strikes)} strike run(s)")
    if inputs.detections:
        parts.append("detections")
    if inputs.mutation:
        parts.append("mutation")
    con.print(f"wrote {out.as_posix()} ({' + '.join(parts)}; {inputs.contain.mode})", markup=False)
    return 0
