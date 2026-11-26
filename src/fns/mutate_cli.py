"""CLI handler for ``fns mutate`` and ``fns demo mutate`` (M5). Read-only."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from fns import __version__
from fns.console import FixtureConsole
from fns.exitcodes import ExitCode
from fns.models.contract import Contract
from fns.models.mutation import MutationReport
from fns.models.snapshot import Snapshot

MARK = {"killed": "KILLED  ", "survived": "SURVIVED", "inconclusive": "INCONCL."}
STYLE = {"killed": "fns.pass", "survived": "fns.fail", "inconclusive": "fns.inconclusive"}


def run(
    contract: Contract,
    snapshot: Snapshot,
    lab: Path | None,
    *,
    harden: bool,
    now: datetime | None = None,
) -> MutationReport:
    from fns.mutate import MutateError, mutate

    if lab is not None and not lab.is_dir():
        raise MutateError(f"lab directory not found: {lab.as_posix()}")
    return mutate(
        contract,
        snapshot,
        lab,
        harden=harden,
        generated_at=now or datetime.now(UTC),
        tool_version=__version__,
    )


def write(report: MutationReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        json.loads(report.canonical_json()), indent=2, sort_keys=True, ensure_ascii=False
    )
    path.write_text(text + "\n", encoding="utf-8", newline="\n")


def exit_code(report: MutationReport, max_survivors: int) -> int:
    if report.baseline_failures:
        return int(ExitCode.CONTRACT_FAILED)
    return 0 if report.total - report.killed <= max_survivors else int(ExitCode.CONTRACT_FAILED)


def render(
    report: MutationReport, con: Console | FixtureConsole, *, diffs: bool, max_survivors: int
) -> None:
    con.print(
        f"Mutation score {report.score} for contract {report.contract} "
        "(modeled: no mutant is applied anywhere)",
        style="bold",
        markup=False,
    )
    if report.hardened_with:
        con.print(
            "baseline: hardened in the model by removing " + ", ".join(report.hardened_with),
            style="fns.muted",
            markup=False,
        )
    if report.baseline_failures:
        con.print(
            f"baseline already has {report.baseline_failures} failing finding(s); a mutant is "
            "killed only by a new failure, so this score says little. Use --harden or fix "
            "the baseline first.",
            style="fns.fail",
            markup=False,
        )
    else:
        con.print(
            f"baseline: no failing findings, {report.baseline_inconclusive} inconclusive "
            "(no modeled path is not a pass; see coverage in `fns contain`)",
            style="fns.muted",
            markup=False,
        )
    for m in report.mutants:
        con.print(
            f"  {MARK[m.outcome]} {m.id}: {m.description}", style=STYLE[m.outcome], markup=False
        )
        if m.new_failures:
            con.print(
                "           now fails: " + "; ".join(m.new_failures),
                style="fns.muted",
                markup=False,
            )
        if m.outcome != "killed":
            con.print(
                "           the contract does not forbid this; add a must_not_reach item, or "
                "accept it as an intended survivor",
                style="fns.muted",
                markup=False,
            )
        if m.terraform_note:
            con.print(f"           terraform: {m.terraform_note}", style="fns.muted", markup=False)
        if diffs and m.terraform_diff and m.outcome != "killed":
            for line in m.terraform_diff.splitlines():
                con.print(f"           {line}", markup=False, highlight=False)
    for n in report.not_applicable:
        con.print(f"  n/a      {n.operator}: {n.reason}", style="fns.muted", markup=False)
    con.print(
        "by operator: "
        + " | ".join(f"{s.operator} {s.killed}/{s.total}" for s in report.by_operator if s.total),
        markup=False,
    )
    survivors = report.total - report.killed
    if not report.baseline_failures:
        verdict = "within" if survivors <= max_survivors else "over"
        con.print(
            f"{survivors} survivor(s), {verdict} the allowed {max_survivors}",
            style="fns.pass" if verdict == "within" else "fns.fail",
            markup=False,
        )
