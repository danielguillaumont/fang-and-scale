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
