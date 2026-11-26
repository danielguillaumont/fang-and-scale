"""The GitHub Action and its workflow: structure, safety, the comment, and a fixture run."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from fns.cli import app
from fns.contain_run import run_demo_contain
from fns.models.report import ContainReport
from fns.report.html import Inputs
from fns.report.markdown import MARKER, md, render_comment

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"
WORKFLOWS = ROOT / ".github" / "workflows"
LAB_RUN = ROOT / "fixtures" / "lab-run-1"
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(/[\w.-]+)*@[0-9a-f]{40}$")  # owner/repo[/path]@sha
runner = CliRunner()


def _load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data


def _steps(doc: dict[str, Any]) -> list[dict[str, Any]]:
    if "runs" in doc:
        return list(doc["runs"]["steps"])
    return [s for job in doc["jobs"].values() for s in job["steps"]]


@pytest.mark.parametrize("path", [ACTION, *sorted(WORKFLOWS.glob("*.yml"))], ids=lambda p: p.name)
def test_third_party_actions_are_pinned_and_scripts_never_interpolate_inputs(path: Path) -> None:
    for step in _steps(_load(path)):
        uses = step.get("uses")
        if uses is not None:
            assert uses == "./" or PINNED.match(uses), f"{path.name}: {uses} is not pinned"
        script = step.get("run", "")
        # Untrusted values reach scripts only through env, never by template expansion.
        assert "${{" not in script, f"{path.name}: template expansion inside run"
    assert not re.search(r"\bsecrets\.[A-Za-z_]", path.read_text(encoding="utf-8"))


def test_blast_radius_workflow_is_least_privilege() -> None:
    doc = _load(WORKFLOWS / "blast-radius.yml")
    on: dict[str, Any] = doc["on"] if "on" in doc else doc[True]  # type: ignore[index]
    assert set(on) == {"pull_request"}  # PyYAML reads the bare key `on` as True
    assert doc["permissions"] == {"contents": "read", "pull-requests": "write"}
    text = (WORKFLOWS / "blast-radius.yml").read_text(encoding="utf-8")
    assert "pull_request_target" not in text
    assert "azure/login" not in text
    checkout = next(s for s in _steps(doc) if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["persist-credentials"] is False


def test_action_contract() -> None:
    doc = _load(ACTION)
    assert doc["runs"]["using"] == "composite"
    assert set(doc["inputs"]) >= {"contract", "snapshot", "probes", "lab", "baseline"}
    run = next(s for s in doc["runs"]["steps"] if s.get("id") == "run")
    assert "--sign offline-test" in run["run"]  # never claims a real signature
    comment = next(
        s for s in doc["runs"]["steps"] if s.get("name") == "Comment on the pull request"
    )
    assert "HEAD_REPO" in comment["run"] and MARKER in comment["run"]


@pytest.fixture(scope="module")
def lab_report(tmp_path_factory: pytest.TempPathFactory) -> ContainReport:
    _, report = run_demo_contain(tmp_path_factory.mktemp("lab"), LAB_RUN)
    return report


def test_comment_headline_delta_and_labels(lab_report: ContainReport) -> None:
    base = lab_report.model_copy(
        update={"summary": lab_report.summary.model_copy(update={"critical": 9})}
    )
    text = render_comment(Inputs(lab_report), base)
    assert text.startswith(MARKER + "\n")
    assert "**Blast radius: 11 critical reachable (+2 vs base)**" in text
    assert "(FIXTURE)" in text and "> FIXTURE:" in text
    assert "Result: **contract failed** (exit 1)" in text
    assert "no change vs base" in render_comment(Inputs(lab_report), lab_report)


def test_tenant_strings_cannot_break_out_or_mention() -> None:
    hostile = "@octocat | <img src=x> `x` [link](http://e) **b** #1\nnext"
    out = md(hostile)
    for bad in ("@octocat", "|", "<img", "`", "[link]", "**", "\n"):
        assert bad not in out
    assert md("must_not_reach #1 &") == "must&#95;not&#95;reach &#35;1 &amp;"


def test_cli_comment(tmp_path: Path) -> None:
    contain = tmp_path / "c.json"
    runner.invoke(
        app,
        [
            "demo",
            "contain",
            "--fixture",
            str(LAB_RUN),
            "--out",
            str(tmp_path),
            "--json",
            str(contain),
        ],
    )
    out = tmp_path / "comment.md"
    result = runner.invoke(app, ["comment", "--contain", str(contain), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8").startswith(MARKER)


def _script(step_id: str) -> str:
    step = next(s for s in _load(ACTION)["runs"]["steps"] if s.get("id") == step_id)
    return str(step["run"])


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None, reason="runs the action's bash script"
)
def test_action_script_on_the_lab_fixture(tmp_path: Path) -> None:
    scout, _ = run_demo_contain(tmp_path / "scout", LAB_RUN)
    snap = tmp_path / "snapshot.json"
    snap.write_text(scout.snapshot.canonical_json(), encoding="utf-8")
    outputs = tmp_path / "out.txt"
    summary = tmp_path / "summary.md"
    env = {
        **os.environ,
        "GITHUB_ACTION_PATH": str(ROOT),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(outputs),
        "GITHUB_STEP_SUMMARY": str(summary),
        "FNS_CONTRACT": str(LAB_RUN / "contract.fns.yaml"),
        "FNS_SNAPSHOT": str(snap),
        "FNS_PROBES": str(LAB_RUN / "probes.json"),
        "FNS_LAB": str(ROOT / "lab"),
        "FNS_BASELINE": "",
    }
    done = subprocess.run(  # noqa: S603
        ["bash", "-c", _script("run")],  # noqa: S607
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    lines = dict(line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines())
    assert lines["exit-code"] == "1"
    body = Path(lines["comment-file"]).read_text(encoding="utf-8")
    assert "mutation 6/8" in body and "TEST signature" in body
    assert summary.read_text(encoding="utf-8") == body


def test_codeql_is_read_only_apart_from_its_results() -> None:
    doc = _load(WORKFLOWS / "codeql.yml")
    assert doc["permissions"] == {}
    (job,) = doc["jobs"].values()
    assert job["permissions"] == {"contents": "read", "security-events": "write"}
    assert set(job["strategy"]["matrix"]["language"]) == {"python", "actions"}


def test_dependabot_watches_every_ecosystem_we_pin() -> None:
    doc = _load(ROOT / ".github" / "dependabot.yml")
    got = {(u["package-ecosystem"], u["directory"]) for u in doc["updates"]}
    assert got == {("uv", "/"), ("github-actions", "/"), ("terraform", "/lab")}
