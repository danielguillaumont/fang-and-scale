"""PR comment (Markdown) for the GitHub Action (M5).

Headline as in PLAN section 5: ``Blast radius: +2 critical reachable · mutation
14/15 · bundle signed``. Tenant strings are untrusted (PLAN section 9): they are
escaped so they cannot break the table, inject HTML, or mention people.
"""

from __future__ import annotations

from collections import Counter
from typing import Final

from fns.models.report import ContainReport
from fns.report.html import COVERAGE_ORDER, EXIT_MEANING, Inputs, ReportInputError, check

MARKER: Final = "<!-- fns:blast-radius -->"
MAX_ROWS: Final = 50


_ESCAPES: Final[dict[int, str]] = str.maketrans(
    {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "|": "&#124;",
        "`": "&#96;",
        "@": "&#64;",
        "[": "&#91;",
        "]": "&#93;",
        "*": "&#42;",
        "_": "&#95;",
        "#": "&#35;",
        "\r": " ",
        "\n": " ",
    }
)


def md(text: object) -> str:
    """Escape for a Markdown table cell or inline text, in one pass (never re-escapes)."""
    return str(text).translate(_ESCAPES)


def _delta(now: int, base: int | None) -> str:
    if base is None:
        return ""
    d = now - base
    return f" ({'+' if d > 0 else ''}{d} vs base)" if d else " (no change vs base)"


def render_comment(inputs: Inputs, baseline: ContainReport | None = None) -> str:
    # The baseline comes from the base branch, so a different contract or snapshot is
    # expected there; only the inputs for this head must agree with each other.
    problems = check(inputs)
    if problems:
        raise ReportInputError("; ".join(problems))
    c = inputs.contain
    b = inputs.bundle
    critical = b.summary.critical if b else c.summary.critical
    exit_code = b.summary.exit_code if b else c.summary.exit_code
    base_critical = baseline.summary.critical if baseline else None
    head = [f"Blast radius: {critical} critical reachable{_delta(critical, base_critical)}"]
    if inputs.mutation:
        head.append(f"mutation {inputs.mutation.score}")
    if b:
        signing = inputs.signing or {}
        signer = signing.get("signer", "unknown")
        if signer == "sigstore":
            staging = signing.get("sigstore_instance") == "staging"
            head.append(
                "bundle signed (Sigstore STAGING)" if staging else "bundle signed (Sigstore)"
            )
        else:
            head.append(
                f"bundle {md(signer)}" + (" (TEST signature)" if signer == "offline-test" else "")
            )
    findings = b.findings if b else c.findings
    counts = Counter(f.coverage for f in findings)
    coverage = " · ".join(f"{s} {counts.get(s, 0)}" for s in COVERAGE_ORDER)
    lines = [
        MARKER,
        f"### Fang & Scale: `{md(c.contract)}`" + (" (FIXTURE)" if c.mode == "FIXTURE" else ""),
        "",
        f"**{' · '.join(head)}**",
        "",
        f"Result: **{md(EXIT_MEANING.get(exit_code, exit_code))}** (exit {exit_code}) · "
        f"legitimate use failed {b.summary.still_do_failed if b else c.summary.still_do_failed}"
        f" · inconclusive {b.summary.inconclusive if b else c.summary.inconclusive}"
        f" of {c.summary.max_inconclusive} allowed",
        "",
        f"Coverage: {coverage}",
        "",
    ]
    if c.mode == "FIXTURE":
        lines += [
            "> FIXTURE: replayed from recorded or hand-written files, not a live tenant.",
            "",
        ]
    rows = sorted(
        findings,
        key=lambda f: (
            {"fail": 0, "inconclusive": 1}.get(f.verdict, 2),
            f.item_kind,
            f.target,
            f.operation,
        ),
    )
    table = [
        "| verdict | item | target | operation | coverage |",
        "| --- | --- | --- | --- | --- |",
    ]
    table += [
        "| "
        + " | ".join(md(v) for v in (f.verdict, f.item_kind, f.target, f.operation, f.coverage))
        + " |"
        for f in rows[:MAX_ROWS]
    ]
    if len(rows) > MAX_ROWS:
        table.append(f"| … | {len(rows) - MAX_ROWS} more | | | |")
    lines += ["<details><summary>Findings</summary>", "", *table, "", "</details>", ""]
    if inputs.mutation:
        survivors = [m for m in inputs.mutation.mutants if m.outcome != "killed"]
        if survivors:
            lines += [
                "<details><summary>Mutation survivors (contract gaps)</summary>",
                "",
                *(f"- {md(m.outcome)}: {md(m.description)}" for m in survivors),
                "",
                "</details>",
                "",
            ]
    lines.append(
        "<sub>Modeled findings are rung 1; only `fns prove` raises the rung. "
        "Read-only: nothing was changed in any tenant.</sub>"
    )
    return "\n".join(lines) + "\n"
