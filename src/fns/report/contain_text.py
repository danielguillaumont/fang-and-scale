"""Terminal rendering of a :class:`ContainReport` (``fns contain``, ``fns demo contain``).

Coverage comes first (PLAN section 5.5), then findings, then the escalation path
behind each failure with its rung and coverage labels, then the verdict.
"""

from __future__ import annotations

from collections import Counter
from typing import Final

from fns.models.evidence import Finding
from fns.models.report import ContainReport, ReachPath
from fns.summary import Printer

VERDICT_STYLE: Final = {"pass": "fns.pass", "fail": "fns.fail", "inconclusive": "fns.inconclusive"}
COVERAGE_ORDER: Final = (
    "verified",
    "evaluated-only",
    "modeled-only",
    "not-assessed",
    "out-of-scope",
)


def _rung(f: Finding) -> str:
    results = [e.rung for e in f.supporting if e.outcome in {"allowed", "denied"}]
    return results[-1] if results else "-"


def _target(f: Finding) -> str:
    return f.target.split(":", 1)[1] if ":" in f.target else f.target


def render_contain(report: ContainReport, out: Printer, *, max_alternatives: int = 0) -> None:
    out.print(
        f"contract {report.contract}  compromised "
        f"{report.compromised_name or '(unresolved)'} {report.compromised or ''}".rstrip(),
        markup=False,
    )
    out.print(
        f"snapshot sha256:{report.snapshot_digest}  {report.mode}  "
        f"semantics v{report.semantics_version}",
        markup=False,
    )
    out.print("evidence: rung 1 (modeled) only; nothing here was observed", style="fns.muted")

    cov = Counter(f.coverage for f in report.findings)
    parts = "  ".join(f"{c}={cov[c]}" for c in COVERAGE_ORDER if cov[c])
    out.print(f"coverage: {parts}", markup=False)

    out.print("Findings", style="fns.brand")
    for f in report.findings:
        item = "not-reach" if f.item_kind == "must_not_reach" else "still-do"
        out.print(
            f"  [{VERDICT_STYLE[f.verdict]}]{f.verdict:<12}[/] {item:<9} {_rung(f):<8} "
            f"{f.coverage:<13} {_target(f)} {f.operation}"
        )

    by_finding: dict[str, list[ReachPath]] = {}
    for p in report.paths:
        by_finding.setdefault(p.finding_id, []).append(p)

    failures = [f for f in report.findings if f.verdict == "fail"]
    if failures:
        out.print("Escalation paths", style="fns.brand")
    for f in failures:
        paths = by_finding.get(f.id, [])
        out.print(
            f"[{VERDICT_STYLE[f.verdict]}]FAIL[/] {f.target} {f.operation}  "
            f"[fns.muted]{_rung(f)} / {f.coverage}[/]"
        )
        if not paths:
            for reason in f.reasons[:2]:
                out.print(f"    {reason}", markup=False)
        for p in paths[: 1 + max_alternatives]:
            if p.rank:
                out.print(f"  alternative {p.rank}:", style="fns.muted")
            for n, step in enumerate(p.steps, 1):
                out.print(f"  {n}. [{step.rule}] {step.text}", markup=False)
                for src in step.sources:
                    out.print(f"       from {src}", style="fns.muted", markup=False)
            for a in p.assumptions:
                out.print(f"     assumes: {a}", style="fns.inconclusive", markup=False)
        hidden = len(paths) - 1 - max_alternatives
        if hidden > 0:
            out.print(f"  (+{hidden} alternative path(s) in the JSON report)", style="fns.muted")

    others = [f for f in report.findings if f.verdict == "inconclusive"]
    if others:
        out.print("Inconclusive", style="fns.inconclusive")
    for f in others:
        out.print(f"  {f.target} {f.operation}: {f.reasons[0]}", markup=False)
        for reason in [r for r in f.reasons[1:] if " resolved to " not in r][:3]:
            out.print(f"      {reason}", style="fns.muted", markup=False)

    s = report.summary
    out.print(
        f"critical reachable: {s.critical}/{s.max_critical_reachable} max  "
        f"must_still_do failed: {s.still_do_failed}  "
        f"inconclusive: {s.inconclusive}/{s.max_inconclusive} max (on_inconclusive: "
        f"{s.on_inconclusive})",
        markup=False,
    )
    if s.warning:
        out.print(f"warning: {s.warning}", style="fns.warn", markup=False)
    for item in s.unaccepted_inconclusive:
        out.print(f"not accepted by the budget: {item}", style="fns.inconclusive", markup=False)
    # Exit 0 is "within budget", never "pass": no finding passes on modeled evidence.
    verdict = {0: "WITHIN BUDGET", 1: "FAILED", 3: "INCONCLUSIVE OVER BUDGET"}[s.exit_code]
    style = {0: "fns.muted", 1: "fns.fail", 3: "fns.inconclusive"}[s.exit_code]
    out.print(f"contract {verdict} (exit {s.exit_code})", style=style, markup=False)
    out.print(f"report sha256:{report.digest()}", style="fns.highlight")
