"""File handling around the pure reach engine: load inputs, write reports.

``fns.contain`` stays free of I/O; this module is what the CLI calls.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fns import __version__
from fns.contain.evaluate import evaluate
from fns.contain.report import build_report
from fns.demo import DEMO_FIXTURE, run_demo_scout
from fns.fixtures.replay import bundled
from fns.models.contract import Contract, load_contract
from fns.models.report import ContainReport
from fns.models.snapshot import Snapshot
from fns.summary import ScoutResult
from fns.yamlio import loads_yaml

CONTRACT_FILE = "contract.fns.yaml"


def load_snapshot(path: Path) -> Snapshot:
    return Snapshot.model_validate_json(path.read_bytes())


def contain(
    contract: Contract, snapshot: Snapshot, *, now: datetime | None = None
) -> ContainReport:
    return build_report(
        evaluate(contract, snapshot),
        generated_at=now or datetime.now(UTC),
        tool_version=__version__,
    )


def write_report(report: ContainReport, path: Path | None, out_dir: Path) -> Path:
    """Write to ``path``, or to ``<out_dir>/reports/<digest>.<mode>.json``."""
    if path is None:
        path = out_dir / "reports" / f"{report.digest()}.{report.mode}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        json.loads(report.canonical_json()), indent=2, sort_keys=True, ensure_ascii=False
    )
    path.write_text(text + "\n", encoding="utf-8", newline="\n")
    return path


def demo_contract(fixture_dir: Path | None) -> Contract:
    if fixture_dir is not None:
        return load_contract(fixture_dir / CONTRACT_FILE)
    text = bundled(DEMO_FIXTURE).joinpath(CONTRACT_FILE).read_text(encoding="utf-8")
    return Contract.model_validate(loads_yaml(text))


def run_demo_contain(
    out_dir: Path, fixture_dir: Path | None = None, contract: Contract | None = None
) -> tuple[ScoutResult, ContainReport]:
    """Replay a fixture through scout, then evaluate its contract. Deterministic."""
    scout = run_demo_scout(out_dir, fixture_dir)
    c = contract or demo_contract(fixture_dir)
    report = contain(c, scout.snapshot, now=scout.snapshot.collected_at)
    return scout, report
