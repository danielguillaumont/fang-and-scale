from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns import __version__
from fns.cli import app
from fns.console import BANNER

runner = CliRunner()

UNBUILT = ["strike", "harden", "prove", "molt"]


def test_version_prints_ascii_banner_and_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
    assert BANNER.splitlines()[1] in result.output
    assert result.output.isascii()


def test_banner_is_ascii() -> None:
    assert BANNER.isascii()


@pytest.mark.parametrize("command", UNBUILT)
def test_unbuilt_commands_exit_2(command: str) -> None:
    result = runner.invoke(app, [command])
    assert result.exit_code == 2
    assert "not implemented in M1" in result.output


def test_scout_without_scope_manifest_exits_1(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scout", "--scope", str(tmp_path / "missing.yaml")])
    assert result.exit_code == 1
    assert "scope manifest not found" in result.output


def test_help_lists_every_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ["scout", "contain", *UNBUILT]:
        assert command in result.output


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output
