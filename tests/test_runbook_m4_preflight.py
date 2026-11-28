"""The M4 preflight (``docs/runbooks/m4-preflight.md``): the checklist before session A.

It repeats numbers that live elsewhere (the lab's defaults, the strike plan's
lifetime, the runbook's prompting commands). These checks fail when one of them
changes and the page doesn't.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.test_runbook_m4_live import BLOCKS, PROMPTS, _code

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = (ROOT / "docs" / "runbooks" / "m4-preflight.md").read_text(encoding="utf-8")
VARIABLES = (ROOT / "lab" / "variables.tf").read_text(encoding="utf-8")
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _default(name: str) -> str:
    m = re.search(rf'variable "{name}" \{{.*?default\s+=\s+(\S+)', VARIABLES, re.S)
    assert m is not None, name
    return m[1]


def test_nothing_real_and_no_azure_call() -> None:
    assert GUID.findall(PREFLIGHT) == []
    assert re.findall(r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}", PREFLIGHT) == []
    assert "```" not in PREFLIGHT  # a checklist, not commands to run


def test_the_clocks_match_the_lab_and_the_strike_plan() -> None:
    from fns.strike.plan import PLAN_LIFETIME

    assert f"**scope: {_default('scope_valid_days')} days** from A2" in PREFLIGHT
    assert f"**strike window: {_default('strike_valid_hours')} hours** from C1" in PREFLIGHT
    assert PLAN_LIFETIME.total_seconds() == 3600
    assert "**Plan: 1 hour** from C3 to C4" in PREFLIGHT
    assert "**Sentinel trial: 31 days** from B1's apply" in PREFLIGHT
    assert f"`monitoring_daily_quota_gb` = {_default('monitoring_daily_quota_gb')} GB" in PREFLIGHT
    # The runbook's certificates: AddHours(23), never more than a day.
    assert "each is valid for 23 hours" in PREFLIGHT


def test_every_prompting_command_in_the_runbook_is_listed() -> None:
    prompting = {
        _code(ln) for block in BLOCKS for ln in block.splitlines() if PROMPTS.search(_code(ln))
    }
    assert prompting
    for command in prompting:
        assert f"`{command}`" in PREFLIGHT, command


def test_the_budget_stays_off_on_azure_for_students() -> None:
    assert _default("budget_alert_email") == '""'
    assert "**`budget_alert_email` is empty**" in PREFLIGHT


def test_it_links_the_runbook_and_the_runbook_links_it() -> None:
    assert "[`m4-live-run.md`](m4-live-run.md)" in PREFLIGHT
    runbook = (ROOT / "docs" / "runbooks" / "m4-live-run.md").read_text(encoding="utf-8")
    assert "[`m4-preflight.md`](m4-preflight.md)" in runbook


def test_claude_code_is_kept_away_from_the_signed_in_session() -> None:
    assert "**Claude Code in manual mode**" in PREFLIGHT
    for cmd in ("`az`", "`terraform`", "`fns strike`", "`fns prove`"):
        assert cmd in PREFLIGHT, cmd


def test_stop_and_emergency_triggers_match_the_runbook() -> None:
    runbook = (ROOT / "docs" / "runbooks" / "m4-live-run.md").read_text(encoding="utf-8")
    for trigger in ("verify FAIL", "needs-emergency-cleanup", "unexpected-success", "exits 5"):
        assert trigger in PREFLIGHT, trigger
    for word in ("`verify FAIL`", "`needs-emergency-cleanup`", "`unexpected-success`"):
        assert word in runbook, word
