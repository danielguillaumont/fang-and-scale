"""CLI handlers for ``fns report`` and ``fns demo report`` (M5). Read-only: writes one HTML file."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from fns.console import FixtureConsole
from fns.exitcodes import ExitCode
from fns.models.bundle import EvidenceBundle
from fns.models.mutation import MutationReport
from fns.models.report import ContainReport
from fns.report.html import Inputs, ReportInputError, render_html

BUNDLE_FILE = "bundle.json"
SIGNING_FILE = "signing.json"


def load_inputs(contain: Path, mutation: Path | None, prove_dir: Path | None) -> Inputs:
    report = ContainReport.model_validate_json(contain.read_bytes())
    mut = MutationReport.model_validate_json(mutation.read_bytes()) if mutation else None
    return Inputs(report, mut, *load_inputs_bundle(prove_dir))


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
    bundle = EvidenceBundle.model_validate_json((prove_dir / BUNDLE_FILE).read_bytes())
    signing = None
    sig = prove_dir / SIGNING_FILE
    if sig.exists():
        raw = json.loads(sig.read_text(encoding="utf-8"))
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
    if inputs.mutation:
        parts.append("mutation")
    con.print(f"wrote {out.as_posix()} ({' + '.join(parts)}; {inputs.contain.mode})", markup=False)
    return 0
