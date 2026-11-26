"""The README only names commands that exist and files that are in the repository."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
GROUPS = {"demo", "scope", "detections"}
runner = CliRunner()


def _commands() -> list[list[str]]:
    found: set[tuple[str, ...]] = set()
    pattern = r"(?:uv run fns |`fns )([a-z][a-z-]*)(?: ([a-z][a-z-]*))?"
    for first, second in re.findall(pattern, README):
        found.add((first, second) if first in GROUPS and second else (first,))
    return [list(c) for c in sorted(found)]


@pytest.mark.parametrize("command", _commands(), ids=" ".join)
def test_readme_command_exists(command: list[str]) -> None:
    result = runner.invoke(app, [*command, "--help"])
    assert result.exit_code == 0, result.output


def test_readme_paths_exist() -> None:
    paths = set(re.findall(r"`((?:docs|fixtures|contracts|lab|schemas)/[\w./-]+)`", README))
    for path in sorted(paths):
        if path.endswith("lab-run-3"):  # an example of what the reader would record
            continue
        assert (ROOT / path).exists(), path


def test_readme_contract_snippet_matches_the_example() -> None:
    example = (ROOT / "contracts" / "examples" / "billing-agent.fns.yaml").read_text(
        encoding="utf-8"
    )
    snippet = README.split("```yaml", 1)[1].split("```", 1)[0]
    for line in snippet.splitlines():
        if line.strip() and not line.startswith("#"):
            assert line.rstrip() in example, line
