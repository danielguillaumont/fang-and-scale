"""The M6 design notes stay design notes, and stay true about the code they describe."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT_ID = (ROOT / "docs" / "milestones" / "M6-agent-id.md").read_text(encoding="utf-8")
BAKEOFF = (ROOT / "docs" / "milestones" / "M6-bakeoff.md").read_text(encoding="utf-8")


def test_the_bakeoff_says_it_is_notes_and_lists_its_pending_decisions() -> None:
    assert "**Status: design notes only.** Nothing here is built." in BAKEOFF
    assert "## Decisions this needs" in BAKEOFF and "pending review" in BAKEOFF


def test_the_agent_id_notes_say_exactly_what_is_built() -> None:
    assert "**Status: design notes, except the first step.**" in AGENT_ID
    assert "## Decisions this needs" in AGENT_ID and "pending review" in AGENT_ID
    assert "approved 2026-11-27 and\n   built" in AGENT_ID


def test_the_agent_id_first_step_is_in_the_code() -> None:
    # "The gap today" says the collector recognises the three types and that
    # findings are not assessed. Keep it true; the behaviour is in test_agent_id.py.
    graph = (ROOT / "src" / "fns" / "adapters" / "azure" / "graph.py").read_text(encoding="utf-8")
    snapshot = (ROOT / "src" / "fns" / "models" / "snapshot.py").read_text(encoding="utf-8")
    for odata in ("agentIdentity", "agentIdentityBlueprint", "agentIdentityBlueprintPrincipal"):
        assert f'"#microsoft.graph.{odata}"' in snapshot
        assert f"`{odata}`" in AGENT_ID
    assert "AGENT_ID_ODATA_TYPES" in graph
    assert '"Agent ID inheritance not modeled"' in snapshot
    assert "agent-id-inheritance:not-modeled" in AGENT_ID
    assert "## The gap today" in AGENT_ID
    assert (ROOT / "tests" / "contain" / "test_agent_id.py").is_file()


def test_every_lab_check_is_numbered_once() -> None:
    rows = re.findall(r"^\| (V-A\d) \|", AGENT_ID, re.M)
    assert rows == [f"V-A{i}" for i in range(1, len(rows) + 1)]
    assert len(rows) == 6
    for ref in set(re.findall(r"\(V-A(\d)\)", AGENT_ID)):
        assert f"V-A{ref}" in rows, ref  # every "(V-An)" in the text has its row


def test_the_bakeoff_judge_is_code_that_exists() -> None:
    tfmap = (ROOT / "src" / "fns" / "harden" / "tfmap.py").read_text(encoding="utf-8")
    assert "def apply_to_snapshot(" in tfmap
    assert (ROOT / "src" / "fns" / "harden" / "minimize.py").is_file()
    for named in ("fns.harden.tfmap", "fns.harden.minimize", "fns.verify"):
        assert named in BAKEOFF
    assert "Never in CI" in BAKEOFF
    assert not re.search(r"claude-|gpt-|gemini-", BAKEOFF, re.I)  # no models picked yet


def test_microsoft_sources_are_learn_links() -> None:
    links = re.findall(r"\]\((https://[^)]+)\)", AGENT_ID)
    assert len(links) >= 5
    assert all(u.startswith("https://learn.microsoft.com/") for u in links)
