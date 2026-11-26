"""``fns contain`` and ``fns demo contain``.

M2 gate: fail the seeded contract and print escalation paths with rung and
coverage labels. All of it runs on fixtures, so every line says FIXTURE.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.contain_run import run_demo_contain

ROOT = Path(__file__).resolve().parent
LAB_RUN = ROOT.parent / "fixtures" / "lab-run-1"
LAB_CONTRACT = LAB_RUN / "contract.fns.yaml"
runner = CliRunner()


def _golden(name: str) -> str:
    return (ROOT / "golden" / f"{name}.digest").read_text(encoding="utf-8").strip()


def _digest(output: str) -> str:
    m = re.search(r"report sha256:([0-9a-f]{64})", output)
    assert m, output
    return m.group(1)


def _labelled(output: str) -> bool:
    return all(line.startswith("FIXTURE ") for line in output.splitlines() if line.strip())


@pytest.mark.parametrize(
    ("args", "golden"),
    [([], "demo-contain"), (["--fixture", str(LAB_RUN)], "lab-run-1-contain")],
)
def test_demo_contain_fails_seeded_contract_with_labelled_paths(
    tmp_path: Path, args: list[str], golden: str
) -> None:
    first = runner.invoke(app, ["demo", "contain", "--out", str(tmp_path / "a"), *args])
    second = runner.invoke(app, ["demo", "contain", "--out", str(tmp_path / "b"), *args])
    assert first.exit_code == second.exit_code == 1, first.output
    assert _labelled(first.output), first.output
    assert "Escalation paths" in first.output
    assert re.search(
        r"FAIL directory:tenant roleAssignments/write\s+modeled / modeled-only", first.output
    )
    assert "[owner-adds-credential]" in first.output
    assert "contract FAILED (exit 1)" in first.output
    assert _digest(first.output) == _digest(second.output) == _golden(golden)


def test_contain_on_a_snapshot_file(tmp_path: Path) -> None:
    scout, _ = run_demo_contain(tmp_path, LAB_RUN)
    out = tmp_path / "r.json"
    args = ["contain", "--contract", str(LAB_CONTRACT), "--snapshot", str(scout.snapshot_path)]
    result = runner.invoke(app, [*args, "--json", str(out), "--alternatives", "1"])
    assert result.exit_code == 1, result.output
    # A FIXTURE snapshot is replayed data: every line is labelled.
    assert _labelled(result.output), result.output
    assert "alternative 1:" in result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["mode"] == "FIXTURE"
    assert report["summary"]["exit_code"] == 1
    assert _digest(result.output) == _golden("lab-run-1-contain")


def test_exit_0_within_budget_is_never_called_a_pass(tmp_path: Path) -> None:
    scout, _ = run_demo_contain(tmp_path, LAB_RUN)
    lenient = tmp_path / "lenient.fns.yaml"
    text = LAB_CONTRACT.read_text(encoding="utf-8")
    lenient.write_text(
        text.replace("max_critical_reachable: 0", "max_critical_reachable: 6"), encoding="utf-8"
    )
    args = ["contain", "--contract", str(lenient), "--snapshot", str(scout.snapshot_path)]
    result = runner.invoke(app, [*args, "--out", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "WITHIN BUDGET" in result.output
    assert "PASS" not in result.output


def test_contain_invalid_inputs_exit_1(tmp_path: Path) -> None:
    missing = runner.invoke(
        app,
        ["contain", "--contract", str(tmp_path / "x.yaml"), "--snapshot", str(tmp_path / "s")],
    )
    assert missing.exit_code == 1
    bad = tmp_path / "s.json"
    bad.write_text("{}", encoding="utf-8")
    invalid = runner.invoke(
        app, ["contain", "--contract", str(LAB_CONTRACT), "--snapshot", str(bad)]
    )
    assert invalid.exit_code == 1
    assert "invalid input" in invalid.output
