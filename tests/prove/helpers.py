"""Build real ``fns prove`` run directories from the lab-run-1 fixture (no Azure)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fns.contain_run import demo_contract, run_demo_contain
from fns.models.assertions import AssertionSet
from fns.models.contract import Contract
from fns.models.report import ContainReport
from fns.models.snapshot import Snapshot
from fns.probes.mock import MockProbe, MockResults, load_results
from fns.probes.runner import ProbeRun
from fns.prove.run import prepare

ROOT = Path(__file__).resolve().parents[2]
LAB_RUN = ROOT / "fixtures" / "lab-run-1"


@dataclass(frozen=True)
class Lab:
    contract: Contract
    snapshot: Snapshot
    report: ContainReport
    results: MockResults


def lab(tmp: Path) -> Lab:
    scout, report = run_demo_contain(tmp / "scout", LAB_RUN)
    return Lab(
        demo_contract(LAB_RUN), scout.snapshot, report, load_results(LAB_RUN / "probes.json")
    )


def prepared(
    tmp: Path, results: MockResults | None = None
) -> tuple[AssertionSet, Path, ProbeRun, Lab]:
    lb = lab(tmp)
    at = lb.snapshot.collected_at
    probe = MockProbe(results or lb.results, at=at)
    _, aset, run_dir, probes = prepare(lb.contract, lb.snapshot, probe, tmp / "out", now=lambda: at)
    return aset, run_dir, probes, lb


def results_with(base: MockResults, **changes: Any) -> MockResults:
    return MockResults.model_validate({**base.model_dump(), **changes})
