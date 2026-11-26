"""What every prove golden decides, for the before/after guard in test_verdict_baseline.py.

``tests/golden/prove-verdicts.json`` was written by this module *before* the
2026-11-26 change that attaches context evidence (denied probes that settle
nothing) to findings. Verdicts, coverage, gaps, reasons, the summary and the
supporting evidence must stay exactly as recorded; only context may be added.

Regenerate only for a change that is meant to alter verdicts, and say so in
the PR: ``uv run python -m tests.prove.baseline``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from fns.cli import app
from fns.fixtures.replay import bundled
from fns.models.bundle import EvidenceBundle

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "tests" / "golden" / "prove-verdicts.json"

GOLDENS: dict[str, Path] = {
    "demo-prove": Path(str(bundled("demo-scout"))),
    "lab-run-1-prove": ROOT / "fixtures" / "lab-run-1",
    "lab-run-2-prove": ROOT / "fixtures" / "lab-run-2",
    "lab-run-3-prove": ROOT / "fixtures" / "lab-run-3",
}


def run(fixture: Path, out: Path) -> EvidenceBundle:
    result = CliRunner().invoke(
        app, ["demo", "prove", "--fixture", str(fixture), "--out", str(out)]
    )
    assert result.exit_code in {0, 1, 3}, result.output
    (bundle_file,) = out.rglob("bundle.json")
    return EvidenceBundle.model_validate_json(bundle_file.read_bytes())


def evidence_row(e: Any) -> dict[str, Any]:
    row: dict[str, Any] = e.model_dump(mode="json")
    row.pop("role", None)
    return row


def decisions(bundle: EvidenceBundle, *, supporting_only: bool = True) -> dict[str, Any]:
    findings = {}
    for f in sorted(bundle.findings, key=lambda f: f.id):
        ev = [e for e in f.evidence if not supporting_only or getattr(e, "role", None) is None]
        findings[f.id] = {
            "target": f.target,
            "operation": f.operation,
            "item_kind": f.item_kind,
            "verdict": f.verdict,
            "coverage": f.coverage,
            "gap": f.gap,
            "reasons": list(f.reasons),
            "evidence": [evidence_row(e) for e in ev],
        }
    return {"summary": bundle.summary.model_dump(mode="json"), "findings": findings}


def main() -> None:
    import tempfile

    out: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name, fixture in GOLDENS.items():
            out[name] = decisions(run(fixture, Path(tmp) / name))
    BASELINE.write_text(
        json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    sys.stdout.write(f"wrote {BASELINE.relative_to(ROOT)}\n")


if __name__ == "__main__":
    main()
