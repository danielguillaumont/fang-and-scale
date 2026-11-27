"""v0.1 release prep: the release workflow, version metadata, changelog, install path.

Nothing here tags or publishes. The checks keep the workflow to what was asked:
it runs only on a ``v*`` tag, refuses a tag that disagrees with the package
version and changelog, builds and writes an SBOM, and makes a *draft* release
that a person publishes. It never uploads to PyPI.
"""

from __future__ import annotations

import importlib.util
import re
import shlex
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from fns import __version__
from fns.cli import app
from tests.test_runbook_m4_live import _resolve

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
VERSION: str = PYPROJECT["project"]["version"]
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
QUICKSTART = (ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
runner = CliRunner()

_spec = importlib.util.spec_from_file_location(
    "release_check", ROOT / "scripts" / "release_check.py"
)
assert _spec is not None and _spec.loader is not None
release_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_check)


def _workflow() -> dict[Any, Any]:
    data: dict[Any, Any] = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    return data


def _steps() -> list[dict[str, Any]]:
    (job,) = _workflow()["jobs"].values()
    steps: list[dict[str, Any]] = job["steps"]
    return steps


def _run_text() -> str:
    return "\n".join(str(s.get("run", "")) for s in _steps())


# --- the workflow ---------------------------------------------------------------------


def test_it_runs_only_on_a_version_tag() -> None:
    on = _workflow()[True]  # YAML 1.1 reads the key `on` as True
    assert on == {"push": {"tags": ["v*"]}}


def test_permissions_are_read_only_except_the_draft() -> None:
    wf = _workflow()
    assert wf["permissions"] == {"contents": "read"}
    (job,) = wf["jobs"].values()
    assert job["permissions"] == {"contents": "write"}
    assert "id-token" not in RELEASE.read_text(encoding="utf-8")


def test_every_action_is_pinned_like_the_other_workflows() -> None:
    uses = [s["uses"] for s in _steps() if "uses" in s]
    assert uses
    others = "\n".join(
        p.read_text(encoding="utf-8") for p in WORKFLOWS.glob("*.yml") if p != RELEASE
    )
    for u in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u), u
        assert u in others, f"{u} is pinned nowhere else; reuse an existing pin"
    for s in _steps():
        if s.get("uses", "").startswith("actions/checkout@"):
            assert s["with"]["persist-credentials"] is False


def test_it_checks_builds_writes_an_sbom_and_drafts_only() -> None:
    text = _run_text()
    order = [
        "scripts/release_check.py",
        "uv sync --locked",
        "poe check",
        "uv build",
        "--format cyclonedx1.5",
        "SHA256SUMS",
        "gh release create",
    ]
    positions = [text.index(needle) for needle in order]
    assert positions == sorted(positions)
    assert "--draft" in text and "--verify-tag" in text
    for publish in ("uv publish", "twine", "pypa/gh-action-pypi-publish", "--latest"):
        assert publish not in RELEASE.read_text(encoding="utf-8"), publish


def test_the_tag_is_passed_through_the_environment_not_inline() -> None:
    for s in _steps():
        assert "${{" not in str(s.get("run", "")), s.get("name")


# --- version, changelog, lock ---------------------------------------------------------


def test_the_installed_version_is_the_package_version() -> None:
    assert __version__ == VERSION == "0.1.0"
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and f"fns {VERSION}" in result.output


def test_version_changelog_and_lock_agree() -> None:
    assert release_check.problems(None) == []


def test_tagging_needs_the_release_date_first() -> None:
    # The changelog says "not tagged yet"; the date goes in right before the tag.
    assert release_check.problems(f"v{VERSION}") == [
        f"CHANGELOG.md's [{VERSION}] section needs its release date, not 'not tagged yet'"
    ]
    assert any("does not match" in p for p in release_check.problems("v9.9.9"))


def test_the_changelog_says_what_did_not_run_live() -> None:
    section = CHANGELOG[CHANGELOG.index(f"## [{VERSION}]") :]
    assert "### Not in 0.1.0" in section
    for needed in ("have not run live", "S4", "`harden --apply` is not built", "Not published"):
        assert needed in section, needed
    for attribution in ("Co-Authored-By", "Generated with", "Claude", "AI-generated"):
        assert attribution not in CHANGELOG


def test_poe_has_the_release_tasks() -> None:
    tasks = PYPROJECT["tool"]["poe"]["tasks"]
    assert "release_check.py" in tasks["release-check"]["cmd"]
    assert "--format cyclonedx1.5" in tasks["sbom"]["cmd"]
    assert "--format cyclonedx1.5 --no-dev --all-extras" in _run_text()


# --- the install path -----------------------------------------------------------------


def test_the_quickstart_commands_exist() -> None:
    lines = [
        re.sub(r"\s+#\s.*$", "", ln).strip()
        for block in re.findall(r"```\n(.*?)```", QUICKSTART, re.S)
        for ln in block.splitlines()
    ]
    fns = [ln.removeprefix("uv run ") for ln in lines if re.match(r"(uv run )?fns ", ln)]
    assert len(fns) >= 9
    for line in fns:
        argv = shlex.split(line.removeprefix("fns "), posix=False)
        cmd, rest = _resolve(argv)
        known = {o for p in cmd.params for o in getattr(p, "opts", [])} | {"--version"}
        for flag in (a for a in rest if a.startswith("--")):
            assert flag in known, (line, flag)


def test_the_install_commands_pin_the_supported_python() -> None:
    assert PYPROJECT["project"]["requires-python"] == ">=3.12,<3.13"
    installs = [ln for ln in QUICKSTART.splitlines() if re.match(r"(pipx|uv tool) install", ln)]
    assert len(installs) == 2
    for ln in installs:
        assert "--python 3.12" in ln and f"@v{VERSION}" in ln
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/QUICKSTART.md" in readme and "--python 3.12" in readme


@pytest.mark.parametrize("command", ["scout", "contain", "prove", "report"])
def test_bundled_replays_the_packaged_set_outside_a_checkout(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["demo", command, "--bundled", "--out", str(tmp_path / "o")])
    assert result.exit_code in {0, 1}, result.output  # contain and prove: the demo contract fails
    lines = [ln for ln in result.output.splitlines() if ln.strip()]
    assert lines and all(ln.startswith("FIXTURE") for ln in lines)
    assert lines[0].endswith("replaying the bundled hand-written demo set (not a recorded lab run)")


def test_without_bundled_nothing_changes_outside_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["demo", "contain"])
    assert result.exit_code == 2 and "or --bundled" in result.output
    missing = runner.invoke(app, ["demo", "contain", "--fixture", "fixtures/nope"])
    assert missing.exit_code == 2 and "no fixture set at fixtures/nope" in missing.output


def test_bundled_and_fixture_together_are_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", "contain", "--bundled", "--fixture", str(tmp_path)])
    assert result.exit_code == 2 and "not both" in result.output
