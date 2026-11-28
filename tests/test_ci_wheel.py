"""The `wheel` CI job: the built wheel, installed in a clean venv, runs the bundled demo.

It guards the install path users take (``pipx install ...@v0.1.0`` then
``fns demo contain --bundled``), which ``poe check`` from a checkout cannot see.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _job() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(CI.read_text(encoding="utf-8"))
    job: dict[str, Any] = doc["jobs"]["wheel"]
    return job


def _run() -> str:
    return "\n".join(str(s.get("run", "")) for s in _job()["steps"])


def test_the_job_builds_and_installs_only_the_wheel() -> None:
    job = _job()
    assert job["name"] == "wheel (install + bundled demo)"
    assert "permissions" not in job  # the workflow's contents: read
    run = _run()
    assert 'uv build --no-sources --wheel --out-dir "$RUNNER_TEMP/dist"' in run
    assert 'uv venv --python 3.12 "$RUNNER_TEMP/venv"' in run
    assert '"$RUNNER_TEMP"/dist/*.whl' in run
    assert "uv sync" not in run and "uv run" not in run  # never the checkout's environment
    setup = [s for s in job["steps"] if "setup-uv" in str(s.get("uses", ""))]
    assert setup and setup[0]["with"]["enable-cache"] is False


def test_the_demo_runs_from_the_venv_outside_the_checkout() -> None:
    demo = [s for s in _job()["steps"] if "demo contain --bundled" in str(s.get("run", ""))]
    assert len(demo) == 1
    step = demo[0]
    assert step["working-directory"] == "${{ runner.temp }}"
    run = step["run"]
    assert '"$RUNNER_TEMP/venv/bin/fns" demo contain --bundled' in run
    assert 'test "$code" -eq 1' in run  # the demo contract fails on purpose
    assert 'grep -qx "FIXTURE contract FAILED (exit 1)" demo.txt' in run
    assert 'grep -v "^FIXTURE" demo.txt' in run  # every line is labelled


def test_the_expected_lines_are_what_the_bundled_demo_prints(tmp_path: Path) -> None:
    """The job's expectations match the real output, so the check can't drift."""
    from typer.testing import CliRunner

    from fns.cli import app

    result = CliRunner().invoke(app, ["demo", "contain", "--bundled", "--out", str(tmp_path / "o")])
    assert result.exit_code == 1, result.output
    lines = [ln for ln in result.output.splitlines() if ln]
    assert "FIXTURE contract FAILED (exit 1)" in lines
    assert all(ln.startswith("FIXTURE") for ln in lines)
