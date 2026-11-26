"""The ``fns`` command line."""

from __future__ import annotations

from typing import Annotated, NoReturn

import typer

from fns.console import make_console, print_banner
from fns.exitcodes import ExitCode

app = typer.Typer(
    name="fns",
    help="Fang & Scale: unit tests for breach blast radius in Microsoft Entra and Azure.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
    pretty_exceptions_enable=False,
)


def _version_callback(value: bool) -> None:
    if value:
        print_banner(make_console())
        raise typer.Exit(ExitCode.OK)


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Fang & Scale: unit tests for breach blast radius in Microsoft Entra and Azure."""


def _not_implemented(command: str, hint: str | None = None) -> NoReturn:
    err = make_console(stderr=True)
    err.print(f"[fns.warn]fns {command}[/]: not implemented in M1.")
    if hint:
        err.print(hint, style="fns.muted")
    raise typer.Exit(ExitCode.NOT_IMPLEMENTED)


@app.command()
def scout() -> None:
    """Read-only snapshot of RBAC, Graph permissions, owners and directory roles."""
    _not_implemented(
        "scout",
        "Live collection arrives in M1 Phase B. Try `fns demo scout` to replay fixtures.",
    )


@app.command()
def contain() -> None:
    """Assumed-compromise reach and contract evaluation (Antivenom, M2)."""
    _not_implemented("contain")


@app.command()
def strike() -> None:
    """Approved, lab-only attack scenarios (Fang, M6)."""
    _not_implemented("strike")


@app.command()
def harden() -> None:
    """Smallest Terraform diff that satisfies a contract (Scale, M4)."""
    _not_implemented("harden")


@app.command()
def prove() -> None:
    """Re-run assertions with separate read-only credentials; signed bundle (M3)."""
    _not_implemented("prove")


@app.command()
def molt() -> None:
    """Diff two snapshots and invalidate stale conclusions (Molt)."""
    _not_implemented("molt")


def main() -> None:
    app()
