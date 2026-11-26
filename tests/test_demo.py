"""Phase A gate: ``fns demo scout`` is labelled, deterministic and matches the golden digest."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.fixtures.replay import bundled
from fns.models.snapshot import Snapshot

ROOT = Path(__file__).resolve().parent
DEMO_SCOUT = str(bundled("demo-scout"))  # hand-written, for tests
GOLDEN = (ROOT / "golden" / "demo-scout.digest").read_text(encoding="utf-8").strip()

runner = CliRunner()


def _run(out: Path) -> tuple[str, str]:
    result = runner.invoke(app, ["demo", "scout", "--out", str(out), "--fixture", DEMO_SCOUT])
    assert result.exit_code == 0, result.output
    digest_line = next(line for line in result.output.splitlines() if "digest sha256:" in line)
    return result.output, digest_line.rsplit("sha256:", 1)[1].strip()


def test_every_output_line_is_labelled_fixture(tmp_path: Path) -> None:
    output, _ = _run(tmp_path)
    lines = [line for line in output.splitlines() if line.strip()]
    assert len(lines) > 10
    assert all(line.startswith("FIXTURE ") for line in lines), output


def test_digest_is_stable_across_runs_and_matches_golden(tmp_path: Path) -> None:
    _, first = _run(tmp_path / "a")
    _, second = _run(tmp_path / "b")
    _, third = _run(tmp_path / "a")  # same journal, new run
    assert first == second == third == GOLDEN


def test_snapshot_file_is_fixture_mode_and_self_consistent(tmp_path: Path) -> None:
    _, digest = _run(tmp_path)
    path = tmp_path / "snapshots" / f"{digest}.FIXTURE.json"
    assert path.is_file()
    raw = path.read_bytes()
    assert b"\r\n" not in raw
    snap = Snapshot.model_validate(json.loads(raw))
    assert snap.mode == "FIXTURE"
    assert snap.digest() == digest


def test_demo_journals_every_gate_decision(tmp_path: Path) -> None:
    _run(tmp_path)
    conn = sqlite3.connect(tmp_path / "journal.sqlite")
    try:
        (mode,) = conn.execute("SELECT mode FROM runs").fetchone()
        counts = dict(
            conn.execute("SELECT decision, COUNT(*) FROM gate_decisions GROUP BY decision")
        )
        (results,) = conn.execute("SELECT COUNT(*) FROM gate_results").fetchone()
    finally:
        conn.close()
    assert mode == "FIXTURE"
    assert counts == {"allowed": 28}
    assert results == 28


def test_demo_failure_is_labelled_on_stderr(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    result = runner.invoke(app, ["demo", "scout", "--out", str(blocker)])
    assert result.exit_code == 2
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert lines
    assert all(line.startswith("FIXTURE ") for line in lines)
    assert "demo failed" in result.output


@pytest.mark.parametrize("command", ["scout", "contain", "prove", "report", "mutate"])
def test_demo_commands_default_to_the_recorded_lab_run(command: str, tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", command, "--out", str(tmp_path)])
    assert "Replaying fixture 'fixtures/lab-run-3'" in result.output, result.output
    assert "demo-scout" not in result.output


def test_demo_outside_a_checkout_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["demo", "contain", "--out", str(tmp_path / "o")])
    assert result.exit_code == 2, result.output
    assert "run from a repository checkout" in result.output
    assert all(line.startswith("FIXTURE ") for line in result.output.splitlines() if line.strip())
