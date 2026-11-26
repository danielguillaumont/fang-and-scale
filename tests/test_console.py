from __future__ import annotations

import io

import pytest

from fns import console as c


def _style_hex(name: str) -> str | None:
    style = c.THEME.styles[name]
    assert style.color is not None
    return style.color.triplet.hex if style.color.triplet else style.color.name


@pytest.mark.parametrize(
    ("style", "expected"),
    [
        ("fns.pass", c.VENOM),
        ("fns.highlight", c.VENOM),
        ("fns.inconclusive", c.SCALE_COPPER),
        ("fns.warn", c.SCALE_COPPER),
        ("fns.muted", c.SLATE),
    ],
)
def test_theme_uses_brand_palette(style: str, expected: str) -> None:
    assert _style_hex(style) == expected.lower()


def test_fail_uses_standard_red_not_brand() -> None:
    assert _style_hex("fns.fail") == "red"


def test_venom_is_only_used_for_pass_and_highlight() -> None:
    venom_styles = {
        name
        for name, style in c.THEME.styles.items()
        if style.color and style.color.triplet and style.color.triplet.hex == c.VENOM.lower()
    }
    assert venom_styles == {"fns.pass", "fns.highlight"}


def test_no_color_env_strips_ansi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    buf = io.StringIO()
    con = c.make_console(file=buf, force_terminal=True)
    con.print("ok", style="fns.pass")
    assert "\x1b[38" not in buf.getvalue()


def test_color_applied_on_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    buf = io.StringIO()
    con = c.make_console(file=buf, force_terminal=True)
    con.print("ok", style="fns.pass")
    assert "\x1b[" in buf.getvalue()


def test_long_lines_are_not_wrapped_off_terminal() -> None:
    buf = io.StringIO()
    con = c.make_console(file=buf)
    long_path = "/runner/work/" + "x" * 150 + "/contract.schema.json"
    con.print(f"stale {long_path}")
    assert long_path in buf.getvalue()


def _fixture_console(
    encoding: str = "utf-8", width: int = 60
) -> tuple[c.FixtureConsole, io.StringIO]:
    class Buf(io.StringIO):
        @property
        def encoding(self) -> str:  # type: ignore[override]
            return enc

    enc = encoding
    buf = Buf()
    con = c.make_console(file=buf)
    con.width = width
    return c.FixtureConsole(con), buf


def test_fixture_console_labels_every_line_of_a_table() -> None:
    from rich.table import Table

    fc, buf = _fixture_console()
    table = Table(title="t")
    table.add_column("a")
    table.add_row("x\ny")
    fc.print(table)
    fc.print("one\ntwo")
    fc.print("")
    lines = buf.getvalue().splitlines()
    assert len(lines) >= 7
    assert all(line.startswith("FIXTURE") for line in lines)


def test_fixture_console_uses_ascii_boxes_on_non_utf_streams() -> None:
    from rich.table import Table

    fc, buf = _fixture_console(encoding="cp1252")
    table = Table()
    table.add_column("a")
    table.add_row("x")
    fc.print(table)
    assert buf.getvalue().isascii()


def test_fixture_console_label_survives_long_lines() -> None:
    fc, buf = _fixture_console(width=40)
    fc.print("x" * 200)
    lines = buf.getvalue().splitlines()
    assert all(line.startswith("FIXTURE") for line in lines)
