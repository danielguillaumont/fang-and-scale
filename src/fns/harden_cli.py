"""CLI handlers for M4 offline: ``fns harden``, ``fns record``, ``fns detections``.

Kept out of ``fns.cli`` so the main module stays a thin command table. All three
are read-only: ``harden`` prints a diff and a plan hash and never applies it.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError
from rich.console import Console

from fns.console import FixtureConsole
from fns.exitcodes import ExitCode
from fns.yamlio import YamlError


def harden(
    con: Console | FixtureConsole,
    err: Console,
    contract_path: Path,
    snapshot_path: Path,
    lab_dir: Path,
    out: Path | None,
) -> int:
    from fns.contain_run import load_snapshot
    from fns.harden.minimize import NoProposalError, minimize
    from fns.harden.tfmap import TfParseError
    from fns.models.contract import load_contract

    try:
        contract = load_contract(contract_path)
        snapshot = load_snapshot(snapshot_path)
    except (OSError, ValidationError, YamlError) as exc:
        err.print(f"invalid input: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        return int(ExitCode.INVALID_INPUT)
    if not lab_dir.is_dir():
        err.print(f"lab directory not found: {lab_dir.as_posix()}", style="fns.fail", markup=False)
        return int(ExitCode.INVALID_INPUT)
    if snapshot.mode == "FIXTURE" and not isinstance(con, FixtureConsole):
        con = FixtureConsole(con)
    try:
        p = minimize(contract, snapshot, lab_dir)
    except NoProposalError as exc:
        con.print(f"no proposal: {exc}", style="fns.fail", markup=False)
        return int(ExitCode.CONTRACT_FAILED)
    except (TfParseError, OSError) as exc:
        err.print(f"invalid input: {type(exc).__name__}: {exc}", style="fns.fail", markup=False)
        return int(ExitCode.INVALID_INPUT)
    con.print("Proposal (modeled: rung 1 until `fns prove` confirms it)", style="bold")
    con.print(
        f"before: critical reachable {p.before.critical}; "
        f"legitimate use allowed {len(p.before.still_do_allowed)}",
        markup=False,
    )
    con.print(
        f"after:  critical reachable {p.after.critical}; "
        f"legitimate use allowed {len(p.after.still_do_allowed)}",
        markup=False,
    )
    if not p.levers:
        con.print("the contract already holds in the model; nothing to change", markup=False)
    for lever in p.levers:
        con.print(f"  change {lever.address}: {lever.description}", markup=False)
    for alt in p.alternatives:
        con.print(
            "  alternative: " + " + ".join(lever.address for lever in alt),
            style="fns.muted",
            markup=False,
        )
    con.print(
        f"searched {p.evaluated} combination(s) of {len(p.candidates)} candidate lever(s)",
        style="fns.muted",
        markup=False,
    )
    for address, reason in p.rejected:
        con.print(f"  not proposed {address}: {reason}", style="fns.muted", markup=False)
    for line in p.diff.splitlines():
        con.print(line, markup=False, highlight=False)
    con.print(f"plan sha256:{p.plan_hash}", markup=False)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(p.diff, encoding="utf-8", newline="\n")
        con.print(f"wrote {out.as_posix()} (not applied)", style="fns.muted", markup=False)
    con.print(
        "not applied: `fns harden --apply` needs the --approve <plan-hash> flow (not built)",
        style="fns.muted",
        markup=False,
    )
    return 0


def record(
    con: Console,
    err: Console,
    logs: list[Path],
    identity: str,
    contract_path: Path | None,
    out: Path | None,
) -> int:
    from fns.harden.record import RecordError, load_rows, merge, still_do_items
    from fns.harden.record import record as do_record
    from fns.models.contract import load_contract

    try:
        rec = do_record(load_rows(logs), identity)
        contract = load_contract(contract_path) if contract_path else None
    except (RecordError, OSError, ValidationError, YamlError) as exc:
        err.print(f"invalid input: {exc}", style="fns.fail", markup=False)
        return int(ExitCode.INVALID_INPUT)
    con.print(
        f"{rec.rows} row(s): {len(rec.resource_ops)} recorded resource operation(s), "
        f"{rec.failed} failed, {rec.other_identity} by other identities, "
        f"{sum(rec.unmapped.values())} unmapped",
        markup=False,
    )
    for item in sorted(rec.directory_ops):
        con.print(
            f"  directory {item.operation}: seen, not written (must_still_do holds resources "
            "only in contract v1)",
            style="fns.muted",
            markup=False,
        )
    for key, count in sorted(rec.unmapped.items()):
        con.print(f"  unmapped {key} x{count}", style="fns.muted", markup=False)
    items = still_do_items(rec)
    if contract is None:
        text = json.dumps({"must_still_do": items}, indent=2)
        con.print(text, markup=False, highlight=False)
        if out is not None:
            out.write_text(text + "\n", encoding="utf-8", newline="\n")
        return 0
    try:
        m = merge(contract, rec)
    except RecordError as exc:
        err.print(str(exc), style="fns.fail", markup=False)
        return int(ExitCode.INVALID_INPUT)
    for label in m.added:
        con.print(f"  added {label} (source: recorded)", markup=False)
    for label in m.already:
        con.print(f"  already declared {label}", style="fns.muted", markup=False)
    for label in m.conflicts:
        con.print(
            f"  CONFLICT {label}: also in must_not_reach; left out for you to decide",
            style="fns.fail",
            markup=False,
        )
    if out is not None:
        from fns.yamlio import dumps_yaml

        out.write_text(
            dumps_yaml(m.contract.model_dump(mode="json")), encoding="utf-8", newline="\n"
        )
        con.print(f"wrote {out.as_posix()}", style="fns.muted", markup=False)
    return int(ExitCode.CONTRACT_FAILED) if m.conflicts else 0


def detections_check(con: Console, directory: Path) -> int:
    from fns.harden.coverage import coverage_gaps
    from fns.harden.detections import lint, load_exempt, load_rules

    rules, errors = load_rules(directory)
    for r in rules:
        errors.extend(f"{r.id}: {p}" for p in lint(r))
    try:
        exempt = load_exempt(directory)
    except (ValueError, YamlError) as exc:
        errors.append(f"EXEMPT.yaml: {exc}")
        exempt = {}
    errors.extend(coverage_gaps(rules, exempt))
    for e in errors:
        con.print(f"  {e}", style="fns.fail", markup=False)
    con.print(f"{len(rules)} rule(s), {len(errors)} problem(s)", markup=False)
    return int(ExitCode.CHECK_FAILED) if errors else 0


def detections_export(con: Console, directory: Path, params: list[str], out: Path) -> int:
    from fns.harden.detections import load_rules, sentinel_rule

    values: dict[str, str] = {}
    for p in params:
        key, sep, value = p.partition("=")
        if not sep:
            raise typer.BadParameter(f"expected name=value, got {p!r}")
        values[key] = value
    rules, errors = load_rules(directory)
    if errors:
        for e in errors:
            con.print(e, style="fns.fail", markup=False)
        return int(ExitCode.INVALID_INPUT)
    out.mkdir(parents=True, exist_ok=True)
    for r in rules:
        try:
            body = sentinel_rule(r, values)
        except ValueError as exc:
            con.print(str(exc), style="fns.fail", markup=False)
            return int(ExitCode.USAGE)
        (out / f"{r.id}.json").write_text(
            json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
    con.print(f"wrote {len(rules)} rule body(ies) to {out.as_posix()} (not deployed)", markup=False)
    return 0
