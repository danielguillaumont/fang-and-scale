"""docs/PUBLIC-READINESS.md: the required-checks command names real PR checks."""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs" / "PUBLIC-READINESS.md").read_text(encoding="utf-8")
CI = ROOT / ".github" / "workflows" / "ci.yml"
GITHUB_ACTIONS_APP_ID = 15368


def _command() -> tuple[dict[str, Any], str]:
    section = DOC.split("## Require CI to pass", 1)[1].split("\n## ", 1)[0]
    (block,) = re.findall(r"```\n(.*?)\n```", section, flags=re.S)
    (line,) = block.splitlines()
    match = re.fullmatch(r"'(\{.*\})' \| (gh api .*)", line)
    assert match, line
    return json.loads(match.group(1)), match.group(2)


def _pr_job_names(path: Path) -> set[str]:
    """Check names GitHub gives the workflow's jobs: `name` with the matrix expanded."""
    doc: dict[Any, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for key, job in doc["jobs"].items():
        name = str(job.get("name", key))
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        axes = sorted(matrix)
        for values in itertools.product(*(matrix[a] for a in axes)):
            expanded = name
            for axis, value in zip(axes, values, strict=True):
                expanded = expanded.replace(f"${{{{ matrix.{axis} }}}}", str(value))
            names.add(expanded)
    return names


def test_the_command_is_one_put_to_main_protection() -> None:
    _, call = _command()
    assert call == (
        "gh api -X PUT repos/danielguillaumont/fang-and-scale/branches/main/protection --input -"
    )


def test_the_required_checks_are_exactly_the_ci_jobs_on_pull_requests() -> None:
    body, _ = _command()
    checks = body["required_status_checks"]["checks"]
    assert {c["context"] for c in checks} == _pr_job_names(CI)
    assert {c["app_id"] for c in checks} == {GITHUB_ACTIONS_APP_ID}
    doc: dict[Any, Any] = yaml.safe_load(CI.read_text(encoding="utf-8"))
    on: dict[str, Any] = doc["on"] if "on" in doc else doc[True]  # YAML 1.1: bare `on` is True
    assert "pull_request" in on
    assert on["pull_request"] is None  # every PR, no path or branch filter
    for job in doc["jobs"].values():
        assert "if" not in job  # never skipped
    assert _pr_job_names(CI) == {
        "check (ubuntu-latest)",
        "check (windows-latest)",
        "lab (terraform fmt + validate)",
    }


def test_the_command_keeps_what_is_on_now() -> None:
    body, _ = _command()
    assert body["allow_force_pushes"] is False
    assert body["allow_deletions"] is False
    assert body["required_pull_request_reviews"] is None
    assert body["restrictions"] is None
    assert body["enforce_admins"] is False
