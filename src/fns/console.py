"""Rich console, brand theme and banner.

Palette (docs/PLAN.md section 11): Venom is the single accent and is used only
for pass/highlight; fail uses standard red. Bone and Obsidian are not applied as
default text/background so output stays readable on light and dark terminals.
"""

from __future__ import annotations

from typing import IO, Final

from rich.console import Console
from rich.theme import Theme

from fns import __version__

OBSIDIAN: Final = "#0E1116"
BONE: Final = "#ECE8DF"
VENOM: Final = "#B8F03A"
SCALE_COPPER: Final = "#B87333"
SLATE: Final = "#5B6573"

THEME: Final = Theme(
    {
        "fns.pass": f"bold {VENOM}",
        "fns.highlight": VENOM,
        "fns.fail": "bold red",
        "fns.inconclusive": f"bold {SCALE_COPPER}",
        "fns.warn": SCALE_COPPER,
        "fns.muted": SLATE,
        "fns.brand": f"bold {SCALE_COPPER}",
        "fns.fixture": f"bold reverse {SCALE_COPPER}",
    }
)

# ASCII only: renders on any Windows code page and in CI logs.
BANNER: Final = r"""
  _____                    ___     ____            _
 |  ___|_ _ _ __   __ _   ( _ )   / ___|  ___ __ _| | ___
 | |_ / _` | '_ \ / _` |  / _ \/\ \___ \ / __/ _` | |/ _ \
 |  _| (_| | | | | (_| | | (_>  <  ___) | (_| (_| | |  __/
 |_|  \__,_|_| |_|\__, |  \___/\/ |____/ \___\__,_|_|\___|
                  |___/
""".strip("\n")

TAGLINE: Final = "Challenge the defence. Reduce the damage. Prove the improvement."


def make_console(
    *,
    file: IO[str] | None = None,
    stderr: bool = False,
    force_terminal: bool | None = None,
) -> Console:
    """Build a themed console. Rich honours NO_COLOR and non-TTY output itself."""
    return Console(
        theme=THEME,
        file=file,
        stderr=stderr,
        force_terminal=force_terminal,
        highlight=False,
        soft_wrap=True,  # never wrap messages: paths and IDs must stay copy-pastable
    )


def print_banner(console: Console) -> None:
    console.print(BANNER, style="fns.brand", markup=False)
    console.print(TAGLINE, style="fns.muted")
    console.print(f"fns {__version__}")
