"""The ``fns`` command line."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

from fns.console import make_console, print_banner
from fns.exitcodes import ExitCode
from fns.inputcap import MAX_RECORD_BYTES, read_capped

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


strike_app = typer.Typer(
    help="Approved, lab-only strikes: plan, approve by hash, run with undo (M4).",
    no_args_is_help=True,
)
app.add_typer(strike_app, name="strike")

_FIXTURE_OPT = typer.Option(help="Replay this recorded strike set (FIXTURE) instead of live.")
_SCOPE_OPT = typer.Option(help="Live: the scope manifest with a strike: block.")
_SCOUT_OPT = typer.Option(help="Live: Azure CLI config dir signed in as sp-fns-scout.")
_AGENT_OPT = typer.Option(help="Live: Azure CLI config dir signed in as sp-billing-agent.")


@strike_app.command("plan")
def strike_plan(
    strikes: Annotated[str, typer.Option(help="S1,S2,S3 before harden; D-1,...,D-5 after.")],
    fixture: Annotated[Path | None, _FIXTURE_OPT] = None,
    scope: Annotated[Path, _SCOPE_OPT] = Path("scope.lab.yaml"),
    scout_config: Annotated[Path | None, _SCOUT_OPT] = None,
    out: Annotated[Path, typer.Option(help="Directory for <run id>/plan.json.")] = Path(
        ".fns/strike"
    ),
) -> None:
    """Read the pre-state as the scout and write the plan. Sends no write."""
    from fns import strike_cli

    raise typer.Exit(
        strike_cli.plan(
            make_console(),
            make_console(stderr=True),
            strikes=strikes,
            fixture=fixture,
            scope=scope,
            scout_config=scout_config,
            out=out,
        )
    )


def _strike_run(cleanup_only: bool, **kwargs: Any) -> None:
    from fns import strike_cli

    raise typer.Exit(
        strike_cli.run(
            make_console(), make_console(stderr=True), cleanup_only=cleanup_only, **kwargs
        )
    )


@strike_app.command("run")
def strike_run(
    plan: Annotated[Path, typer.Option(help="plan.json written by `fns strike plan`.")],
    approve: Annotated[str, typer.Option(help="The plan hash printed by `fns strike plan`.")],
    fixture: Annotated[Path | None, _FIXTURE_OPT] = None,
    scope: Annotated[Path, _SCOPE_OPT] = Path("scope.lab.yaml"),
    agent_config: Annotated[Path | None, _AGENT_OPT] = None,
    scout_config: Annotated[Path | None, _SCOUT_OPT] = None,
    journal: Annotated[
        Path | None, typer.Option(help="Journal file (default: next to the plan).")
    ] = None,
) -> None:
    """Run an approved plan: every write journaled, every undo run, then verified."""
    _strike_run(
        False,
        plan_path=plan,
        approve=approve,
        fixture=fixture,
        scope=scope,
        agent_config=agent_config,
        scout_config=scout_config,
        journal_path=journal,
    )


@strike_app.command("cleanup")
def strike_cleanup(
    plan: Annotated[Path, typer.Option(help="plan.json of the run to clean up.")],
    approve: Annotated[str, typer.Option(help="The same plan hash the run was approved with.")],
    journal: Annotated[Path, typer.Option(help="That run's journal file.")],
    fixture: Annotated[Path | None, _FIXTURE_OPT] = None,
    scope: Annotated[Path, _SCOPE_OPT] = Path("scope.lab.yaml"),
    agent_config: Annotated[Path | None, _AGENT_OPT] = None,
    scout_config: Annotated[Path | None, _SCOUT_OPT] = None,
) -> None:
    """Finish every undo the journal shows as missing, then verify (after a crash)."""
    _strike_run(
        True,
        plan_path=plan,
        approve=approve,
        fixture=fixture,
        scope=scope,
        agent_config=agent_config,
        scout_config=scout_config,
        journal_path=journal,
    )


@app.command()
def harden(
    contract: Annotated[Path, typer.Option(help="Contract file (*.fns.yaml).")],
    snapshot: Annotated[Path, typer.Option(help="Snapshot JSON written by `fns scout`.")],
    lab: Annotated[Path, typer.Option(help="Terraform directory to propose changes to.")] = Path(
        "lab"
    ),
    out: Annotated[
        Path | None, typer.Option(help="Write the proposed diff here (never applied).")
    ] = None,
    apply: Annotated[bool, typer.Option("--apply", help="Not available yet.")] = False,
) -> None:
    """Propose the smallest Terraform diff that satisfies a contract (M4, read-only)."""
    if apply:
        make_console(stderr=True).print(
            "--apply is not available: writes need the --approve <plan-hash> flow (rule 1)",
            style="fns.fail",
        )
        raise typer.Exit(ExitCode.NOT_IMPLEMENTED)
    from fns import harden_cli

    raise typer.Exit(
        harden_cli.harden(make_console(), make_console(stderr=True), contract, snapshot, lab, out)
    )


@app.command()
def record(
    logs: Annotated[list[Path], typer.Argument(help="Log Analytics rows exported as JSON.")],
    identity: Annotated[str, typer.Option(help="Object ID of the identity to record.")],
    contract: Annotated[
        Path | None, typer.Option(help="Merge recorded items into this contract.")
    ] = None,
    out: Annotated[Path | None, typer.Option(help="Write the result here.")] = None,
) -> None:
    """Turn logged operations into must_still_do items (source: recorded) (M4)."""
    from fns import harden_cli

    raise typer.Exit(
        harden_cli.record(make_console(), make_console(stderr=True), logs, identity, contract, out)
    )


@app.command()
def mutate(
    contract: Annotated[Path, typer.Option(help="Contract file (*.fns.yaml).")],
    snapshot: Annotated[Path, typer.Option(help="Snapshot JSON written by `fns scout`.")],
    lab: Annotated[
        Path | None,
        typer.Option(help="Terraform directory: render each mutant as a diff against it."),
    ] = None,
    harden_first: Annotated[
        bool,
        typer.Option("--harden", help="Apply the `fns harden` proposal (in the model) first."),
    ] = False,
    max_survivors: Annotated[int, typer.Option(min=0, help="Survivors allowed.")] = 0,
    diff: Annotated[bool, typer.Option(help="Print the Terraform diff of each survivor.")] = False,
    json_out: Annotated[Path | None, typer.Option("--json", help="Write the report here.")] = None,
) -> None:
    """Weaken the defence one grant at a time; the contract must notice each (M5)."""
    from pydantic import ValidationError

    from fns import mutate_cli
    from fns.console import FixtureConsole
    from fns.contain_run import load_snapshot
    from fns.models.contract import load_contract
    from fns.mutate import MutateError
    from fns.yamlio import YamlError

    err = make_console(stderr=True)
    try:
        c = load_contract(contract)
        s = load_snapshot(snapshot)
        report = mutate_cli.run(c, s, lab, harden=harden_first)
    except (MutateError, OSError, ValidationError, YamlError) as exc:
        err.print(f"invalid input: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    con = FixtureConsole(make_console()) if s.mode == "FIXTURE" else make_console()
    mutate_cli.render(report, con, diffs=diff, max_survivors=max_survivors)
    if json_out is not None:
        mutate_cli.write(report, json_out)
        con.print(f"wrote {json_out.as_posix()}", style="fns.muted", markup=False)
    raise typer.Exit(mutate_cli.exit_code(report, max_survivors))


@app.command()
def report(
    contain: Annotated[Path, typer.Option(help="Report JSON from `fns contain --json`.")],
    mutation: Annotated[
        Path | None, typer.Option(help="Report JSON from `fns mutate --json`.")
    ] = None,
    prove_dir: Annotated[
        Path | None, typer.Option("--prove", help="Run directory written by `fns prove`.")
    ] = None,
    out: Annotated[Path, typer.Option(help="HTML file to write.")] = Path(".fns/report.html"),
    strike: Annotated[
        list[Path] | None,
        typer.Option(help="A `fns strike run` directory (plan.json and strike-run.json); repeat."),
    ] = None,
    detections: Annotated[
        Path | None,
        typer.Option(help="Detection results per strike (YAML, D5), for one of the --strike runs."),
    ] = None,
) -> None:
    """Write a static HTML report: coverage, graph, findings, proof, strikes, mutation."""
    from pydantic import ValidationError

    from fns import report_cli
    from fns.console import FixtureConsole

    err = make_console(stderr=True)
    try:
        inputs = report_cli.load_inputs(
            contain, mutation, prove_dir, strikes=strike or [], detections=detections
        )
    except (OSError, ValidationError, ValueError) as exc:
        err.print(f"invalid input: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    con = FixtureConsole(make_console()) if inputs.contain.mode == "FIXTURE" else make_console()
    raise typer.Exit(report_cli.write(inputs, out, con, err))


@app.command()
def comment(
    contain: Annotated[Path, typer.Option(help="Report JSON from `fns contain --json`.")],
    baseline: Annotated[
        Path | None, typer.Option(help="Contain report JSON from the base branch, for deltas.")
    ] = None,
    mutation: Annotated[
        Path | None, typer.Option(help="Report JSON from `fns mutate --json`.")
    ] = None,
    prove_dir: Annotated[
        Path | None, typer.Option("--prove", help="Run directory written by `fns prove`.")
    ] = None,
    out: Annotated[Path, typer.Option(help="Markdown file to write.")] = Path(".fns/comment.md"),
) -> None:
    """Write the pull-request comment (Markdown) used by the GitHub Action (M5)."""
    from pydantic import ValidationError

    from fns import report_cli
    from fns.models.report import ContainReport
    from fns.report.html import ReportInputError
    from fns.report.markdown import render_comment

    err = make_console(stderr=True)
    try:
        inputs = report_cli.load_inputs(contain, mutation, prove_dir)
        base = (
            ContainReport.model_validate_json(read_capped(baseline, MAX_RECORD_BYTES))
            if baseline
            else None
        )
        text = render_comment(inputs, base)
    except ReportInputError as exc:
        err.print(f"refusing to mix runs: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (OSError, ValidationError, ValueError) as exc:
        err.print(f"invalid input: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8", newline="\n")
    typer.echo(f"wrote {out.as_posix()}")


detections_app = typer.Typer(help="Detection rules as code (M4).", no_args_is_help=True)
app.add_typer(detections_app, name="detections")


@detections_app.command("check")
def detections_check(
    directory: Annotated[Path, typer.Option("--dir", help="Rule directory.")] = Path("detections"),
) -> None:
    """Lint every rule and check that the reach model is covered."""
    from fns import harden_cli

    raise typer.Exit(harden_cli.detections_check(make_console(), directory))


@detections_app.command("export")
def detections_export(
    param: Annotated[
        list[str] | None, typer.Option(help="name=value for a rule parameter (repeatable).")
    ] = None,
    directory: Annotated[Path, typer.Option("--dir", help="Rule directory.")] = Path("detections"),
    out: Annotated[Path, typer.Option(help="Directory for the rule bodies.")] = Path(
        ".fns/detections"
    ),
    terraform: Annotated[
        Path | None,
        typer.Option(
            help="Write the rules as one JSON file for lab/monitoring.tf instead "
            "(placeholders kept; Terraform fills them at apply time)."
        ),
    ] = None,
    check: Annotated[
        bool, typer.Option("--check", help="With --terraform: fail if the file is out of date.")
    ] = False,
) -> None:
    """Render Sentinel scheduled alert rule bodies as JSON (not deployed)."""
    from fns import harden_cli

    if terraform is not None:
        raise typer.Exit(
            harden_cli.detections_export_terraform(make_console(), directory, terraform, check)
        )
    if check:
        raise typer.BadParameter("--check needs --terraform")
    raise typer.Exit(harden_cli.detections_export(make_console(), directory, param or [], out))


_AFTER_STRIKE_OPT = typer.Option(
    help="A `fns strike run` directory after harden: its D-1 to D-5 results become evidence "
    "(they can only add context or fail a finding, never pass one)."
)


@app.command()
def prove(
    contract: Annotated[Path, typer.Option(help="Contract file (*.fns.yaml).")],
    snapshot: Annotated[Path, typer.Option(help="Snapshot JSON written by `fns scout`.")],
    probes: Annotated[
        Path | None,
        typer.Option(help="Probe results to replay (FIXTURE). Use this or --live."),
    ] = None,
    live: Annotated[
        bool,
        typer.Option(
            "--live",
            help="Run the probes against the lab as the signed-in test identity (needs az login).",
        ),
    ] = False,
    scope: Annotated[
        Path, typer.Option(help="Scope manifest for --live (written by `uv run poe lab-up`).")
    ] = Path("scope.lab.yaml"),
    record: Annotated[
        Path | None,
        typer.Option(
            help="With --live: also write sanitized probes.json into this scout recording."
        ),
    ] = None,
    out: Annotated[Path, typer.Option(help="Directory for runs/<run id>/.")] = Path(".fns"),
    sign: Annotated[
        str, typer.Option(help="offline-test (labelled TEST), sigstore (CI with OIDC), none.")
    ] = "offline-test",
    identity: Annotated[str, typer.Option(help="Label for who the verifier ran as.")] = (
        "unspecified"
    ),
    after_strike: Annotated[Path | None, _AFTER_STRIKE_OPT] = None,
) -> None:
    """Freeze assertions, run probes, and verify in a separate process (M3).

    With --probes the results are replayed (FIXTURE). With --live every probe is a
    GET or HEAD through the scope gate, as the test identity the token belongs to.
    Exit codes follow `fns contain`; 4 means the scope or the identity refused the
    run, 5 that the verifier refused the evidence.
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
    if live == (probes is not None):
        err.print("give exactly one of --probes FILE or --live", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.USAGE)
    if record is not None and not live:
        err.print("--record needs --live", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.USAGE)
    try:
        c = load_contract(contract)
        snap = load_snapshot(snapshot)
        results = load_results(probes) if probes is not None else None
    except (OSError, ValidationError, YamlError) as exc:
        err.print(f"invalid input: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    if results is not None:
        probe = MockProbe(results, at=snap.collected_at)
        _run_prove(c, snap, probe, out, sign, identity, after_strike)
    _run_live_prove(c, snap, scope, out, record, sign, identity, after_strike)


def _run_live_prove(
    c: Any,
    snap: Any,
    scope: Path,
    out: Path,
    record: Path | None,
    sign: str,
    identity: str,
    after_strike: Path | None = None,
) -> None:
    from pydantic import ValidationError

    from fns.journal.sqlite import JournalError
    from fns.models.scope import ScopeExpiredError
    from fns.prove.live import LiveProveError, ProberNotAllowedError, run_live_prove
    from fns.prove.strikes import AfterStrikeError
    from fns.scope.credentials import CredentialError, PrincipalMismatchError, TenantMismatchError
    from fns.yamlio import YamlError

    con = make_console()
    err = make_console(stderr=True)
    try:
        done = run_live_prove(
            c,
            snap,
            scope,
            out,
            record=record,
            signer=sign,  # type: ignore[arg-type]  # checked by the caller
            identity=identity,
            after_strike=after_strike,
        )
    except AfterStrikeError as exc:
        err.print(
            f"--after-strike refused: {exc}. No probe was sent.", style="fns.fail", markup=False
        )
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (TenantMismatchError, PrincipalMismatchError, ProberNotAllowedError) as exc:
        err.print(f"refused: {exc}. No probe was sent.", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.SCOPE_DENIED) from exc
    except FileNotFoundError as exc:
        err.print(f"scope manifest not found: {scope.as_posix()}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (ScopeExpiredError, ValidationError, YamlError) as exc:
        err.print(f"invalid scope manifest: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except LiveProveError as exc:
        err.print(f"cannot start live probes: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except CredentialError as exc:
        err.print(
            f"{exc}. Sign in as the test identity first (docs/runbooks/m3-live-run.md)",
            style="fns.fail",
            markup=False,
        )
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (JournalError, OSError) as exc:
        err.print(f"prove failed: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    who = done.prober
    con.print(
        f"LIVE probes as object {who.object_id} (appid {who.app_id or 'none'})",
        style="fns.brand",
        markup=False,
    )
    for line in done.result.output.splitlines():
        typer.echo(line)
    if done.recorded is not None:
        con.print(f"recorded {done.recorded.as_posix()}", style="fns.muted", markup=False)
        for line in done.omitted:
            con.print(f"  not recorded (cannot be replayed): {line}", markup=False)
    con.print(f"run directory {done.result.run_dir.as_posix()}", style="fns.muted", markup=False)
    raise typer.Exit(done.result.exit_code)


def _run_prove(
    c: Any,
    snap: Any,
    probe: Any,
    out: Path,
    sign: str,
    identity: str,
    after_strike: Path | None = None,
) -> None:
    from datetime import UTC, datetime

    from fns.console import FixtureConsole
    from fns.prove.run import prove as run_prove
    from fns.prove.strikes import AfterStrikeError

    fixed = snap.collected_at if snap.mode == "FIXTURE" or probe.mode == "FIXTURE" else None

    def now() -> datetime:
        return fixed or datetime.now(UTC)

    try:
        result = run_prove(
            c,
            snap,
            probe,
            out,
            now=now,
            signer=sign,  # type: ignore[arg-type]
            identity=identity,
            after_strike=after_strike,
        )
    except AfterStrikeError as exc:
        make_console(stderr=True).print(
            f"--after-strike refused: {exc}. Nothing was recorded.", style="fns.fail", markup=False
        )
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
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
    """Re-verify a prove run: signature, subject digests, and re-derived verdicts.

    Exit 5 if the evidence is invalid; 2 if RUN is not a directory.
    """
    from fns.prove.run import check_run

    if not run.is_dir():
        make_console(stderr=True).print(
            f"not a run directory: {run.as_posix()}", style="fns.fail", markup=False
        )
        raise typer.Exit(ExitCode.INVALID_INPUT)

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
            raise typer.Exit(ExitCode.CHECK_FAILED)
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
    """Validate scope.yaml and print what it allows. Exit 2 if invalid or expired."""
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
        app_id = f" app_id {ident.app_id}" if ident.app_id else ""
        con.print(f"  {ident.object_id} {ident.kind} {ident.name}{app_id}", markup=False)
    if m.data_objects:
        con.print(f"data objects {len(m.data_objects)} (prove reads only these)")
        for obj in m.data_objects:
            con.print(f"  {obj.operation} on {obj.resource}", markup=False)

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
    help="Replay recorded fixtures (output is labelled FIXTURE).", no_args_is_help=True
)
app.add_typer(demo_app, name="demo")

LAB_RUN = Path("fixtures/lab-run-3")
"""The live lab run recorded in M2 (``lab-run-1`` is the M1 one). The demo commands
replay it by default, so they need a repository checkout; the hand-written demo-scout
set is for tests."""


_BUNDLED_OPT = typer.Option(
    "--bundled",
    help="Replay the hand-written demo set shipped in the package (works without a checkout).",
)


def _need_fixture(fixture: Path, err: Any, *, bundled: bool = False) -> Path:
    """The fixture set to replay: ``--fixture``, or with ``--bundled`` the packaged one.

    ``pipx install`` users have no ``fixtures/`` directory; ``--bundled`` gives them the
    hand-written ``demo-scout`` set that ships in the package, and the line printed
    says so. Without it, a missing set is an error, as before.
    """
    if bundled:
        if fixture != LAB_RUN:
            err.print("choose --fixture or --bundled, not both", style="fns.fail", markup=False)
            raise typer.Exit(ExitCode.USAGE)
        from fns.fixtures.replay import bundled as bundled_set

        err.print(
            "replaying the bundled hand-written demo set (not a recorded lab run)",
            style="fns.muted",
            markup=False,
        )
        return Path(str(bundled_set("demo-scout")))
    if not fixture.joinpath("manifest.json").is_file():
        err.print(
            f"no fixture set at {fixture.as_posix()}: run from a repository checkout, "
            "or pass --fixture <recorded set>, or --bundled",
            style="fns.fail",
            markup=False,
        )
        raise typer.Exit(ExitCode.INVALID_INPUT)
    return fixture


@demo_app.command("scout")
def demo_scout(
    out: Annotated[Path, typer.Option(help="Directory for the journal and snapshots.")] = Path(
        ".fns"
    ),
    fixture: Annotated[Path, typer.Option(help="Recorded fixture set to replay.")] = LAB_RUN,
    bundled: Annotated[bool, _BUNDLED_OPT] = False,
) -> None:
    """Replay a recorded lab run through the scope gate and collector (labelled FIXTURE)."""
    from pydantic import ValidationError

    from fns.console import FixtureConsole
    from fns.demo import render, run_demo_scout
    from fns.fixtures.replay import FixtureError
    from fns.journal.sqlite import JournalError
    from fns.models.scope import ScopeExpiredError
    from fns.yamlio import YamlError

    con = FixtureConsole(make_console())
    err = FixtureConsole(make_console(stderr=True))
    fixture = _need_fixture(fixture, err, bundled=bundled)
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
    render(result, con, fixture.as_posix())


@demo_app.command("contain")
def demo_contain(
    out: Annotated[
        Path, typer.Option(help="Directory for the journal, snapshot and report.")
    ] = Path(".fns"),
    fixture: Annotated[
        Path, typer.Option(help="Recorded fixture set to replay (uses its contract.fns.yaml).")
    ] = LAB_RUN,
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
    bundled: Annotated[bool, _BUNDLED_OPT] = False,
) -> None:
    """Replay a fixture through scout, then run `fns contain` on it (labelled FIXTURE).

    The seeded lab contract fails on purpose: exit 1 is the expected result.
    """
    from pydantic import ValidationError

    from fns.console import FixtureConsole
    from fns.contain_run import run_demo_contain, write_report
    from fns.fixtures.replay import FixtureError
    from fns.journal.sqlite import JournalError
    from fns.models.contract import load_contract
    from fns.models.scope import ScopeExpiredError
    from fns.report.contain_text import render_contain
    from fns.yamlio import YamlError

    con = FixtureConsole(make_console())
    err = FixtureConsole(make_console(stderr=True))
    fixture = _need_fixture(fixture, err, bundled=bundled)
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
    con.print(
        f"Replaying fixture {fixture.as_posix()!r}; no network calls are made.", style="fns.muted"
    )
    render_contain(report, con, max_alternatives=alternatives)
    path = write_report(report, json_out, out)
    con.print(f"wrote {path.as_posix()}", style="fns.muted", markup=False)
    raise typer.Exit(report.summary.exit_code)


@demo_app.command("mutate")
def demo_mutate(
    fixture: Annotated[
        Path, typer.Option(help="Recorded fixture set (uses its contract.fns.yaml).")
    ] = LAB_RUN,
    lab: Annotated[Path, typer.Option(help="The lab Terraform the fixture was recorded from.")] = (
        Path("lab")
    ),
    out: Annotated[Path, typer.Option(help="Directory for the journal and snapshot.")] = Path(
        ".fns"
    ),
    diff: Annotated[bool, typer.Option(help="Print the Terraform diff of each survivor.")] = False,
    json_out: Annotated[Path | None, typer.Option("--json", help="Write the report here.")] = None,
) -> None:
    """Harden the lab fixture in the model, then mutate it (labelled FIXTURE).

    Needs a repository checkout: the lab fixture and lab/*.tf. Survivors are
    contract gaps, so exit 1 is the expected result.
    """
    from pydantic import ValidationError

    from fns import mutate_cli
    from fns.console import FixtureConsole
    from fns.contain_run import demo_contract, run_demo_contain
    from fns.fixtures.replay import FixtureError
    from fns.journal.sqlite import JournalError
    from fns.models.scope import ScopeExpiredError
    from fns.mutate import MutateError
    from fns.yamlio import YamlError

    con = FixtureConsole(make_console())
    err = FixtureConsole(make_console(stderr=True))
    if not fixture.is_dir() or not lab.is_dir():
        err.print(
            f"needs {fixture.as_posix()} and {lab.as_posix()}/ (run from a repository checkout)",
            style="fns.fail",
            markup=False,
        )
        raise typer.Exit(ExitCode.INVALID_INPUT)
    try:
        scout, _ = run_demo_contain(out, fixture)
        report = mutate_cli.run(
            demo_contract(fixture),
            scout.snapshot,
            lab,
            harden=True,
            now=scout.snapshot.collected_at,
        )
    except (
        FixtureError,
        JournalError,
        MutateError,
        ScopeExpiredError,
        ValidationError,
        YamlError,
        OSError,
    ) as exc:
        err.print(f"demo failed: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    con.print(
        f"Replaying fixture {fixture.as_posix()!r}; no network calls are made.", style="fns.muted"
    )
    mutate_cli.render(report, con, diffs=diff, max_survivors=0)
    if json_out is not None:
        mutate_cli.write(report, json_out)
        con.print(f"wrote {json_out.as_posix()}", style="fns.muted", markup=False)
    raise typer.Exit(mutate_cli.exit_code(report, 0))


@demo_app.command("report")
def demo_report(
    out: Annotated[Path, typer.Option(help="Directory for the journal, runs and report.")] = Path(
        ".fns"
    ),
    fixture: Annotated[Path, typer.Option(help="Recorded fixture set to replay.")] = LAB_RUN,
    lab: Annotated[
        Path, typer.Option(help="Lab Terraform, for the mutation section (skipped if missing).")
    ] = Path("lab"),
    bundled: Annotated[bool, _BUNDLED_OPT] = False,
) -> None:
    """Run contain and prove (and mutate, for a lab fixture) on a fixture; write the HTML report.

    Everything is replayed from files and labelled FIXTURE. Probe results come from the
    fixture's probes.json: recorded live (lab-run-3) or hand-written (the others).
    """
    from pydantic import ValidationError

    from fns import mutate_cli, report_cli
    from fns.console import FixtureConsole
    from fns.contain_run import demo_contract, run_demo_contain
    from fns.fixtures.replay import FixtureError
    from fns.journal.sqlite import JournalError
    from fns.models.scope import ScopeExpiredError
    from fns.mutate import MutateError
    from fns.probes.mock import RESULTS_FILE, MockProbe, MockResults
    from fns.prove.run import prove as run_prove
    from fns.yamlio import YamlError

    con = FixtureConsole(make_console())
    err = FixtureConsole(make_console(stderr=True))
    fixture = _need_fixture(fixture, err, bundled=bundled)
    try:
        scout, contain_report = run_demo_contain(out, fixture)
        snap = scout.snapshot
        c = demo_contract(fixture)
        root = fixture
        results = MockResults.model_validate_json(
            read_capped(root.joinpath(RESULTS_FILE), MAX_RECORD_BYTES)
        )
        proved = run_prove(
            c,
            snap,
            MockProbe(results, at=snap.collected_at),
            out,
            now=lambda: snap.collected_at,
            signer="offline-test",
            identity="fixture-replay",
        )
        mutation = None
        if lab.is_dir() and fixture.joinpath("contract.fns.yaml").is_file():
            mutation = mutate_cli.run(c, snap, lab, harden=True, now=snap.collected_at)
        inputs = report_cli.load_inputs_from(contain_report, mutation, proved.run_dir)
    except (
        FixtureError,
        JournalError,
        MutateError,
        ScopeExpiredError,
        ValidationError,
        YamlError,
        OSError,
    ) as exc:
        err.print(f"demo failed: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    con.print(
        f"Replaying fixture {fixture.as_posix()!r}; no network calls are made.", style="fns.muted"
    )
    raise typer.Exit(
        report_cli.write(inputs, out / f"report.{snap.mode}.html", con, make_console(stderr=True))
    )


@demo_app.command("prove")
def demo_prove(
    out: Annotated[Path, typer.Option(help="Directory for the journal, snapshot and run.")] = Path(
        ".fns"
    ),
    fixture: Annotated[
        Path,
        typer.Option(help="Recorded fixture set to replay (uses its contract and probes.json)."),
    ] = LAB_RUN,
    sign: Annotated[str, typer.Option(help="offline-test or none.")] = "offline-test",
    after_strike: Annotated[Path | None, _AFTER_STRIKE_OPT] = None,
    bundled: Annotated[bool, _BUNDLED_OPT] = False,
) -> None:
    """Replay a fixture, freeze assertions, replay probe results, verify (FIXTURE).

    The banner says whether the probe results were recorded live or hand-written.
    Exit 1 is the expected result.
    """
    from pydantic import ValidationError

    from fns.console import FixtureConsole
    from fns.contain_run import demo_contract
    from fns.demo import run_demo_scout
    from fns.fixtures.replay import FixtureError
    from fns.journal.sqlite import JournalError
    from fns.models.scope import ScopeExpiredError
    from fns.probes.mock import RESULTS_FILE, MockProbe, MockResults
    from fns.yamlio import YamlError

    err = FixtureConsole(make_console(stderr=True))
    if sign not in {"offline-test", "none"}:
        err.print("the demo signs offline only (offline-test or none)", style="fns.fail")
        raise typer.Exit(ExitCode.USAGE)
    fixture = _need_fixture(fixture, err, bundled=bundled)
    try:
        scout_result = run_demo_scout(out, fixture)
        c = demo_contract(fixture)
        root = fixture
        results = MockResults.model_validate_json(
            read_capped(root.joinpath(RESULTS_FILE), MAX_RECORD_BYTES)
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
    FixtureConsole(make_console()).print(
        f"Replaying fixture {fixture.as_posix()!r} with {results.provenance}; no network calls.",
        style="fns.muted",
        markup=False,
    )
    snap = scout_result.snapshot
    probe = MockProbe(results, at=snap.collected_at)
    _run_prove(c, snap, probe, out, sign, "fixture-replay", after_strike)


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


mcp_app = typer.Typer(
    help="A read-only MCP server over stdio: fixtures, contain reports, fns contain (M6).",
    no_args_is_help=True,
)
app.add_typer(mcp_app, name="mcp")


@mcp_app.command("serve")
def mcp_serve(
    fixtures: Annotated[
        Path | None,
        typer.Option(help="A fixtures/ directory to offer besides the bundled sets."),
    ] = None,
    reports: Annotated[
        Path | None,
        typer.Option(help="A directory of ContainReport files (<digest>.<mode>.json) to offer."),
    ] = None,
    include_live: Annotated[
        bool,
        typer.Option(
            "--include-live",
            help="Also offer LIVE reports from --reports. They hold real tenant names and IDs.",
        ),
    ] = False,
) -> None:
    """Serve read-only MCP tools on stdin and stdout until end of input.

    No tool writes or calls a tenant. Only JSON-RPC is written to stdout; give this
    command to an MCP client as its server command.
    """
    import sys

    from fns.mcp.server import Server, serve

    # UTF-8 both ways; stdout writes bare "\n" (no "\r\n" on Windows), stdin accepts either.
    for stream, newline in ((sys.stdin, None), (sys.stdout, "\n")):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", newline=newline)
    server = Server(fixtures=fixtures, reports=reports, include_live=include_live)
    raise typer.Exit(serve(server, sys.stdin, sys.stdout))


def main() -> None:
    """Entry point. An unexpected exception exits 2, never 1: a crash must not look
    like a failed contract to CI."""
    import sys
    import traceback

    try:
        app()
    except Exception:  # noqa: BLE001 - the last line of defence for the exit code contract
        traceback.print_exc()
        sys.stderr.write(f"fns: internal error (exit {int(ExitCode.INTERNAL_ERROR)})\n")
        raise SystemExit(int(ExitCode.INTERNAL_ERROR)) from None
