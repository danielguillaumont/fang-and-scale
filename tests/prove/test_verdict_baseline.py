"""Guard for the 2026-11-26 context-evidence change: verdicts did not move.

``tests/golden/prove-verdicts.json`` was recorded from every prove golden with
the verifier as it was before denied probes were attached to their findings
(commit "baseline of every prove golden's verdicts"). Re-running each golden
now must give the same summary, and for every finding the same verdict,
coverage, gap, reasons and supporting evidence. The evidence list may only
grow, and only with ``role="context"`` entries.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fns.models.bundle import EvidenceBundle
from tests.prove.baseline import BASELINE, GOLDENS, decisions, evidence_row, run

BEFORE: dict[str, Any] = json.loads(BASELINE.read_text(encoding="utf-8"))
GOLDEN_DIR = Path(__file__).resolve().parents[1] / "golden"


@pytest.fixture(scope="module", params=sorted(GOLDENS))
def rerun(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Any:
    name: str = request.param
    return name, run(GOLDENS[name], tmp_path_factory.mktemp(name))


def test_the_baseline_covers_every_prove_golden() -> None:
    on_disk = {p.stem for p in GOLDEN_DIR.glob("*-prove.digest")}
    assert set(BEFORE) == set(GOLDENS) == on_disk


def test_verdicts_coverage_and_summary_are_unchanged(rerun: tuple[str, EvidenceBundle]) -> None:
    name, bundle = rerun
    before, after = BEFORE[name], decisions(bundle)
    assert after["summary"] == before["summary"]
    assert after["findings"].keys() == before["findings"].keys()
    for fid, old in before["findings"].items():
        new = after["findings"][fid]
        for key in ("target", "operation", "item_kind", "verdict", "coverage", "gap", "reasons"):
            assert new[key] == old[key], (name, old["target"], old["operation"], key)
        # supporting evidence is exactly what it was
        assert new["evidence"] == old["evidence"], (name, old["target"], old["operation"])


def test_evidence_lists_only_grow_and_only_with_context(
    rerun: tuple[str, EvidenceBundle],
) -> None:
    name, bundle = rerun
    for f in bundle.findings:
        old = BEFORE[name]["findings"][f.id]["evidence"]
        rows = [evidence_row(e) for e in f.evidence]
        assert all(row in rows for row in old)
        assert len(f.evidence) == len(old) + len(f.context)
        for e in f.context:
            assert e.role == "context" and e.rung != "modeled" and e.artifact_digest


def test_the_golden_digest_is_the_rerun(rerun: tuple[str, EvidenceBundle]) -> None:
    name, bundle = rerun
    assert bundle.digest() == (GOLDEN_DIR / f"{name}.digest").read_text(encoding="utf-8").strip()
