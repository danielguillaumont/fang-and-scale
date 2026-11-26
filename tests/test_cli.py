from __future__ import annotations

import pytest
from typer.testing import CliRunner

from fns import __version__
from fns.cli import app
from fns.console import BANNER

runner = CliRunner()

UNBUILT = ["contain", "strike", "harden", "prove", "molt"]


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


def test_scout_points_to_demo_until_phase_b() -> None:
    result = runner.invoke(app, ["scout"])
    assert result.exit_code == 2
    assert "not implemented in M1" in result.output
    assert "fns demo scout" in result.output


def test_help_lists_every_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ["scout", *UNBUILT]:
        assert command in result.output


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output
