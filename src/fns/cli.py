"""The ``fns`` command line."""

from __future__ import annotations

from pathlib import Path
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
def scout(
    scope: Annotated[
        Path, typer.Option(help="Scope manifest (written by `uv run poe lab-up`).")
    ] = Path("scope.lab.yaml"),
    out: Annotated[Path, typer.Option(help="Directory for the journal and snapshots.")] = Path(
        ".fns"
    ),
    record: Annotated[
        Path | None,
        typer.Option(help="Also save sanitized responses as a fixture set in this directory."),
    ] = None,
) -> None:
    """Read-only snapshot of the tenant in scope.yaml (needs `az login`)."""
    from pydantic import ValidationError

    from fns.journal.sqlite import JournalError
    from fns.models.scope import ScopeExpiredError
    from fns.scope.credentials import CredentialError, TenantMismatchError
    from fns.scout import run_live_scout
    from fns.summary import render_summary
    from fns.yamlio import YamlError

    con = make_console()
    err = make_console(stderr=True)
    try:
        result = run_live_scout(scope, out, record=record)
    except TenantMismatchError as exc:
        err.print(f"tenant pinning: {exc}. No API call was made.", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.SCOPE_DENIED) from exc
    except FileNotFoundError as exc:
        err.print(f"scope manifest not found: {scope.as_posix()}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (ScopeExpiredError, ValidationError, YamlError) as exc:
        err.print(f"invalid scope manifest: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except CredentialError as exc:
        err.print(
            f"{exc}. Sign in first: az login --tenant <tenant_id from the scope manifest>",
            style="fns.fail",
            markup=False,
        )
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (JournalError, OSError) as exc:
        err.print(f"scout failed: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    con.print("LIVE read-only snapshot", style="fns.brand")
    render_summary(result, con)


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


@app.command()
def schema(
    out: Annotated[Path, typer.Option("--out", help="Directory for the generated schemas.")] = Path(
        "schemas"
    ),
    check: Annotated[
        bool, typer.Option("--check", help="Fail if committed schemas differ from the models.")
    ] = False,
) -> None:
    """Write JSON Schemas for scope.yaml, contracts and snapshots."""
    from fns import schema as schema_mod

    con = make_console()
    if check:
        stale = schema_mod.drifted(out)
        if stale:
            err = make_console(stderr=True)
            for path in stale:
                err.print(f"[fns.fail]stale[/] {path.as_posix()}")
            err.print("Run `uv run poe schema` and commit the result.", style="fns.muted")
            raise typer.Exit(ExitCode.CONTRACT_FAILED)
        con.print(f"[fns.pass]ok[/] schemas in {out.as_posix()} are up to date")
        return
    for path in schema_mod.write_all(out):
        con.print(f"wrote {path.as_posix()}")


scope_app = typer.Typer(help="Validate and inspect scope manifests.", no_args_is_help=True)
app.add_typer(scope_app, name="scope")


@scope_app.command("check")
def scope_check(
    path: Annotated[Path, typer.Argument(help="Path to scope.yaml.")],
) -> None:
    """Validate scope.yaml and print what it allows. Exit 1 if invalid or expired."""
    from datetime import UTC, datetime

    from pydantic import ValidationError
    from rich.table import Table

    from fns.models.scope import ScopeExpiredError, load_scope
    from fns.yamlio import YamlError

    con = make_console()
    err = make_console(stderr=True)
    now = datetime.now(UTC)
    try:
        m = load_scope(path, now=now)
    except FileNotFoundError:
        err.print(f"[fns.fail]invalid[/] {path.as_posix()}: file not found")
        raise typer.Exit(ExitCode.INVALID_INPUT) from None
    except (YamlError, ScopeExpiredError) as exc:
        err.print(f"[fns.fail]invalid[/] {path.as_posix()}: ", end="")
        err.print(str(exc), markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from None
    except ValidationError as exc:
        err.print(f"[fns.fail]invalid[/] {path.as_posix()}: {exc.error_count()} error(s)")
        for e in exc.errors():
            loc = ".".join(str(x) for x in e["loc"]) or "(root)"
            err.print(f"  {loc}: {e['msg']}", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from None

    remaining = m.expires_at - now
    con.print(f"[fns.pass]valid[/] {path.as_posix()}")
    con.print(f"tenant        {m.tenant_id}")
    con.print(
        f"expires       {m.expires_at.isoformat()} ({_human(remaining.total_seconds())} left)"
    )
    con.print(
        f"budget        {m.budget.max_api_calls} API calls, {m.budget.max_minutes} min per run"
    )
    con.print(f"subscriptions {len(m.subscription_ids)}")
    for sub in m.subscription_ids:
        con.print(f"  {sub}")
    con.print(f"resource groups {len(m.allowed_resource_groups)}")
    for rg in m.allowed_resource_groups:
        con.print(f"  {rg}")
    con.print(f"test identities {len(m.test_identities)}")
    for ident in m.test_identities:
        con.print(f"  {ident.object_id} {ident.kind} {ident.name}", markup=False)

    table = Table(title="allowed operations", show_lines=False)
    table.add_column("verb")
    table.add_column("operation")
    table.add_column("kind")
    verbs = sorted(m.allowed_operations)
    for verb in verbs:
        for op in m.allowed_operations[verb]:
            table.add_row(verb, op, "read" if _is_read(op) else "write")
    if not verbs:
        table.add_row("-", "(none: every call will be denied)", "-")
    con.print(table)


demo_app = typer.Typer(
    help="Replay bundled fixtures (output is labelled FIXTURE).", no_args_is_help=True
)
app.add_typer(demo_app, name="demo")


@demo_app.command("scout")
def demo_scout(
    out: Annotated[Path, typer.Option(help="Directory for the journal and snapshots.")] = Path(
        ".fns"
    ),
    fixture: Annotated[
        Path | None,
        typer.Option(help="Replay a recorded fixture set instead of the bundled one."),
    ] = None,
) -> None:
    """Replay the bundled demo tenant through the scope gate and collector."""
    from pydantic import ValidationError

    from fns.console import FixtureConsole
    from fns.demo import DEMO_FIXTURE, render, run_demo_scout
    from fns.fixtures.replay import FixtureError
    from fns.journal.sqlite import JournalError
    from fns.models.scope import ScopeExpiredError
    from fns.yamlio import YamlError

    con = FixtureConsole(make_console())
    err = FixtureConsole(make_console(stderr=True))
    try:
        result = run_demo_scout(out, fixture)
    except (
        FixtureError,
        JournalError,
        ScopeExpiredError,
        ValidationError,
        YamlError,
        OSError,
    ) as exc:
        err.print(f"demo failed: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    render(result, con, fixture.as_posix() if fixture else DEMO_FIXTURE)


def _is_read(op: str) -> bool:
    from fns.models.operations import parse_operation

    return parse_operation(op).is_read


def _human(seconds: float) -> str:
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def main() -> None:
    app()
