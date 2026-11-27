"""Control characters from data never reach the terminal (THREAT-MODEL, section 5).

A display name is chosen by anyone who can edit the object. With an ESC in it, it
could clear the screen, hide a line or recolour a verdict. ``SafeConsole`` shows
such characters as escapes instead, and keeps Rich's own styling.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from rich.table import Table
from rich.text import Text
from typer.testing import CliRunner

from fns.cli import app
from fns.console import (
    UNSAFE_CHARS,
    FixtureConsole,
    SafeConsole,
    make_console,
    visible_controls,
)
from fns.fixtures.replay import bundled

HOSTILE = "name\x1b[2J\x1b]0;title\x07\x1b[8mhidden\r\x00\x9b‮evil"


def _console(*, color: bool = True) -> tuple[SafeConsole, io.StringIO]:
    buf = io.StringIO()
    con = make_console(file=buf, force_terminal=color)
    assert isinstance(con, SafeConsole)
    return con, buf


def _raw_controls(out: str) -> list[str]:
    """Control characters in the output that are not part of Rich's own SGR codes."""
    import re

    without_sgr = re.sub(r"\x1b\[[0-9;]*m", "", out)
    return sorted(set(UNSAFE_CHARS.findall(without_sgr)))


def test_visible_controls_escapes_each_kind() -> None:
    assert visible_controls("a\x1bb") == "a\\x1bb"
    assert visible_controls("\x00\x7f\x9b\r") == "\\x00\\x7f\\x9b\\x0d"
    assert visible_controls("‮⁦‏؜") == "\\u202e\\u2066\\u200f\\u061c"
    assert (
        visible_controls("tab\tand\nnewline stay; é ü 中 too")
        == "tab\tand\nnewline stay; é ü 中 too"
    )


@pytest.mark.parametrize("markup", [True, False])
def test_a_hostile_string_prints_as_escapes(markup: bool) -> None:
    con, buf = _console()
    con.print(HOSTILE, markup=markup)
    out = buf.getvalue()
    assert _raw_controls(out) == []
    for shown in ("\\x1b[2J", "\\x1b]0;title", "\\x1b[8mhidden", "\\x0d", "\\x00", "\\u202e"):
        assert shown in out, shown


def test_rich_styles_still_colour_the_output() -> None:
    con, buf = _console()
    con.print("[fns.fail]FAILED[/] " + HOSTILE)
    out = buf.getvalue()
    assert "\x1b[1;31mFAILED" in out  # our own SGR survives
    assert _raw_controls(out) == []


def test_tables_and_text_objects_are_covered() -> None:
    con, buf = _console()
    table = Table()
    table.add_column("display name")
    table.add_row(HOSTILE)
    con.print(table)
    con.print(Text.assemble(("verdict ", "fns.pass"), HOSTILE))
    out = buf.getvalue()
    assert _raw_controls(out) == []
    assert "\\x1b[8mhidden" in out  # the table sized for the escaped text, nothing cropped


def test_the_fixture_console_is_covered_too() -> None:
    con, buf = _console()
    FixtureConsole(con).print(HOSTILE, markup=False)
    lines = buf.getvalue().splitlines()
    assert lines and all("FIXTURE" in ln for ln in lines)
    assert _raw_controls(buf.getvalue()) == []


def test_without_a_terminal_nothing_raw_gets_through_either() -> None:
    con, buf = _console(color=False)
    con.print(HOSTILE, markup=False)
    assert UNSAFE_CHARS.findall(buf.getvalue()) == []


@given(st.text(alphabet=st.characters(codec="utf-8"), max_size=60))
def test_any_string_prints_without_raw_controls(s: str) -> None:
    con, buf = _console()
    con.print(s, markup=False)
    con.print(Text(s))
    assert _raw_controls(buf.getvalue()) == []


def test_a_hostile_display_name_in_a_fixture_reaches_contain_output_escaped(tmp_path: Path) -> None:
    fixture = tmp_path / "hostile"
    fixture.mkdir()
    for node in bundled("demo-scout").iterdir():
        fixture.joinpath(node.name).write_bytes(node.read_bytes())
    exchanges = fixture / "exchanges.json"
    text = exchanges.read_text(encoding="utf-8")
    needle = '"displayName": "app-escalation-target"'
    assert needle in text
    hostile = json.dumps("app-escalation-target\x1b[2J‮")
    exchanges.write_text(text.replace(needle, f'"displayName": {hostile}'), encoding="utf-8")

    result = CliRunner().invoke(
        app, ["demo", "contain", "--fixture", str(fixture), "--out", str(tmp_path / "o")]
    )
    assert result.exit_code == 1, result.output
    assert "app-escalation-target\\x1b[2J\\u202e" in result.output
    assert "\x1b[2J" not in result.output and "‮" not in result.output
