"""The ``fns`` command line."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, NoReturn

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
def contain(
    contract: Annotated[Path, typer.Option(help="Contract file (*.fns.yaml).")],
    snapshot: Annotated[
        Path, typer.Option(help="Snapshot JSON written by `fns scout` (.fns/snapshots/...).")
    ],
    json_out: Annotated[
        Path | None,
        typer.Option("--json", help="Write the report here (default .fns/reports/)."),
    ] = None,
    out: Annotated[Path, typer.Option(help="Directory for reports.")] = Path(".fns"),
    alternatives: Annotated[
        int, typer.Option(min=0, max=3, help="Alternative paths to print per failure.")
    ] = 0,
) -> None:
    """Assumed-compromise reach and contract evaluation (Antivenom). Offline.

    Exit 0 within budget, 1 contract failed, 3 inconclusive over budget.
    """
    from pydantic import ValidationError

    from fns.console import FixtureConsole
    from fns.contain_run import contain as run_contain
    from fns.contain_run import load_snapshot, write_report
    from fns.models.contract import load_contract
    from fns.report.contain_text import render_contain
    from fns.yamlio import YamlError

    err = make_console(stderr=True)
    try:
        c = load_contract(contract)
        snap = load_snapshot(snapshot)
    except FileNotFoundError as exc:
        err.print(f"not found: {exc.filename}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (ValidationError, YamlError, ValueError) as exc:
        err.print(f"invalid input: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    report = run_contain(c, snap)
    con = FixtureConsole(make_console()) if snap.mode == "FIXTURE" else make_console()
    render_contain(report, con, max_alternatives=alternatives)
    path = write_report(report, json_out, out)
    con.print(f"wrote {path.as_posix()}", style="fns.muted", markup=False)
    raise typer.Exit(report.summary.exit_code)


@app.command()
def strike() -> None:
    """Approved, lab-only attack scenarios (Fang, M6)."""
    _not_implemented("strike")


@app.command()
def harden() -> None:
    """Smallest Terraform diff that satisfies a contract (Scale, M4)."""
    _not_implemented("harden")


@app.command()
def prove(
    contract: Annotated[Path, typer.Option(help="Contract file (*.fns.yaml).")],
    snapshot: Annotated[Path, typer.Option(help="Snapshot JSON written by `fns scout`.")],
    probes: Annotated[
        Path,
        typer.Option(help="Probe results to replay (FIXTURE). Live probes arrive in M3 P5."),
    ],
    out: Annotated[Path, typer.Option(help="Directory for runs/<run id>/.")] = Path(".fns"),
    sign: Annotated[
        str, typer.Option(help="offline-test (labelled TEST), sigstore (CI with OIDC), none.")
    ] = "offline-test",
    identity: Annotated[str, typer.Option(help="Label for who the verifier ran as.")] = (
        "unspecified"
    ),
) -> None:
    """Freeze assertions, run probes, and verify in a separate process (M3, offline).

    Exit codes follow `fns contain`; 5 means the verifier refused the evidence.
    """
    from pydantic import ValidationError

    from fns.contain_run import load_snapshot
    from fns.models.contract import load_contract
    from fns.probes.mock import MockProbe, load_results
    from fns.yamlio import YamlError

    err = make_console(stderr=True)
    if sign not in {"offline-test", "sigstore", "none"}:
        err.print(f"unknown signer {sign!r}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.USAGE)
    try:
        c = load_contract(contract)
        snap = load_snapshot(snapshot)
        results = load_results(probes)
    except (OSError, ValidationError, YamlError) as exc:
        err.print(f"invalid input: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    _run_prove(c, snap, MockProbe(results, at=snap.collected_at), out, sign, identity)


def _run_prove(c: Any, snap: Any, probe: Any, out: Path, sign: str, identity: str) -> None:
    from datetime import UTC, datetime

    from fns.console import FixtureConsole
    from fns.prove.run import prove as run_prove

    fixed = snap.collected_at if snap.mode == "FIXTURE" or probe.mode == "FIXTURE" else None

    def now() -> datetime:
        return fixed or datetime.now(UTC)

    result = run_prove(c, snap, probe, out, now=now, signer=sign, identity=identity)  # type: ignore[arg-type]
    for line in result.output.splitlines():
        typer.echo(line)
    con = make_console()
    label = FixtureConsole(con) if result.assertions.mode == "FIXTURE" else con
    label.print(f"run directory {result.run_dir.as_posix()}", style="fns.muted", markup=False)
    raise typer.Exit(result.exit_code)


@app.command()
def verify(
    run: Annotated[Path, typer.Argument(help="A run directory written by `fns prove`.")],
) -> None:
    """Re-verify a prove run: signature, subject digests, and re-derived verdicts."""
    from fns.prove.run import check_run

    code, output = check_run(run)
    for line in output.splitlines():
        typer.echo(line)
    raise typer.Exit(code)


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
    """Write JSON Schemas for scope.yaml, contracts, snapshots and contain reports."""
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


@demo_app.command("contain")
def demo_contain(
    out: Annotated[
        Path, typer.Option(help="Directory for the journal, snapshot and report.")
    ] = Path(".fns"),
    fixture: Annotated[
        Path | None,
        typer.Option(help="Replay a recorded fixture set (uses its contract.fns.yaml)."),
    ] = None,
    contract: Annotated[
        Path | None, typer.Option(help="Evaluate this contract instead of the fixture's.")
    ] = None,
    json_out: Annotated[
        Path | None,
        typer.Option("--json", help="Write the report here (default <out>/reports/)."),
    ] = None,
    alternatives: Annotated[
        int, typer.Option(min=0, max=3, help="Alternative paths to print per failure.")
    ] = 0,
) -> None:
    """Replay a fixture through scout, then run `fns contain` on it (labelled FIXTURE).

    The bundled demo contract fails on purpose: exit 1 is the expected result.
    """
    from pydantic import ValidationError

    from fns.console import FixtureConsole
    from fns.contain_run import run_demo_contain, write_report
    from fns.demo import DEMO_FIXTURE
    from fns.fixtures.replay import FixtureError
    from fns.journal.sqlite import JournalError
    from fns.models.contract import load_contract
    from fns.models.scope import ScopeExpiredError
    from fns.report.contain_text import render_contain
    from fns.yamlio import YamlError

    con = FixtureConsole(make_console())
    err = FixtureConsole(make_console(stderr=True))
    try:
        c = load_contract(contract) if contract is not None else None
        _scout, report = run_demo_contain(out, fixture, c)
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
    source = fixture.as_posix() if fixture else DEMO_FIXTURE
    con.print(f"Replaying fixture {source!r}; no network calls are made.", style="fns.muted")
    render_contain(report, con, max_alternatives=alternatives)
    path = write_report(report, json_out, out)
    con.print(f"wrote {path.as_posix()}", style="fns.muted", markup=False)
    raise typer.Exit(report.summary.exit_code)


@demo_app.command("prove")
def demo_prove(
    out: Annotated[Path, typer.Option(help="Directory for the journal, snapshot and run.")] = Path(
        ".fns"
    ),
    fixture: Annotated[
        Path | None,
        typer.Option(help="Replay a recorded fixture set (uses its contract and probes.json)."),
    ] = None,
    sign: Annotated[str, typer.Option(help="offline-test or none.")] = "offline-test",
) -> None:
    """Replay a fixture, freeze assertions, replay probe results, verify (FIXTURE).

    The probe results are hand-written, not recorded. Exit 1 is the expected result.
    """
    from pydantic import ValidationError

    from fns.console import FixtureConsole
    from fns.contain_run import demo_contract
    from fns.demo import DEMO_FIXTURE, run_demo_scout
    from fns.fixtures.replay import FixtureError, bundled
    from fns.journal.sqlite import JournalError
    from fns.models.scope import ScopeExpiredError
    from fns.probes.mock import RESULTS_FILE, MockProbe, MockResults
    from fns.yamlio import YamlError

    err = FixtureConsole(make_console(stderr=True))
    if sign not in {"offline-test", "none"}:
        err.print("the demo signs offline only (offline-test or none)", style="fns.fail")
        raise typer.Exit(ExitCode.USAGE)
    try:
        scout_result = run_demo_scout(out, fixture)
        c = demo_contract(fixture)
        root = fixture if fixture is not None else bundled(DEMO_FIXTURE)
        results = MockResults.model_validate_json(
            root.joinpath(RESULTS_FILE).read_text(encoding="utf-8")
        )
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
    source = fixture.as_posix() if fixture else DEMO_FIXTURE
    FixtureConsole(make_console()).print(
        f"Replaying fixture {source!r} with hand-written probe results; no network calls.",
        style="fns.muted",
        markup=False,
    )
    snap = scout_result.snapshot
    _run_prove(c, snap, MockProbe(results, at=snap.collected_at), out, sign, "fixture-replay")


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
