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
        if path.endswith("my-run"):  # an example of what the reader would record
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


def test_the_authorized_use_notice_is_near_the_top() -> None:
    head = "\n".join(README.splitlines()[:20])
    assert "**Authorized use only.**" in head
    assert "SECURITY.md" in head


def test_public_repository_files_are_present() -> None:
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "Report a vulnerability" in security
    assert "authorized to test" in security
    assert (ROOT / "CONTRIBUTING.md").is_file()
    owners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    assert "* @danielguillaumont" in owners.splitlines()


def test_readme_has_the_status_and_verification_sections() -> None:
    headings = set(re.findall(r"^## (.+)$", README, flags=re.M))
    assert {"Project status", "Verify a signed result"} <= headings


def test_the_verification_commands_match_the_signing_workflow() -> None:
    """The README pins the identity prove-sign.yml really signs with on main."""
    from fns.verify.main import SIGSTORE_BUNDLE_FILE
    from fns.verify.signing import PRODUCTION_WORKFLOW_REF

    section = README.split("## Verify a signed result", 1)[1].split("\n## ", 1)[0]
    identity = f"https://github.com/{PRODUCTION_WORKFLOW_REF}"
    assert section.count(f"--cert-identity {identity}") == 1
    assert section.count(f"--sigstore-identity {identity}") == 1
    assert f"--bundle run/{SIGSTORE_BUNDLE_FILE}" in section
    assert "--sigstore-instance production" in section
    assert "--trigger push" in section
    assert "--sigstore-issuer https://token.actions.githubusercontent.com" in section
