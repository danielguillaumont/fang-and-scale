"""The M6 design notes stay design notes, and stay true about the code they describe."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGENT_ID = (ROOT / "docs" / "milestones" / "M6-agent-id.md").read_text(encoding="utf-8")
BAKEOFF = (ROOT / "docs" / "milestones" / "M6-bakeoff.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("text", [AGENT_ID, BAKEOFF], ids=["agent-id", "bakeoff"])
def test_they_say_they_are_notes_and_list_their_pending_decisions(text: str) -> None:
    assert "**Status: design notes only.** Nothing here is built." in text
    assert "## Decisions this needs" in text and "pending review" in text


def test_the_agent_id_gap_is_still_the_gap() -> None:
    # The note says the collector does not recognise agent identities. When it does,
    # update "The gap today" in docs/milestones/M6-agent-id.md, then this test.
    graph = (ROOT / "src" / "fns" / "adapters" / "azure" / "graph.py").read_text(encoding="utf-8")
    assert "agentIdentity" not in graph
    assert '"managedIdentity" if kind == "ManagedIdentity" else "servicePrincipal"' in graph
    assert "## The gap today" in AGENT_ID


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
