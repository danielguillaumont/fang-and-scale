"""docs/proposals/conditional-access.md is design only (2026-11-28, pending review).

Until Daniel picks an option, the code is option A: the surface stays not
collected, no collector reads policies and the lab grants no Policy.Read.All.
"""

from __future__ import annotations

from pathlib import Path

from fns.adapters.azure import arm, graph
from fns.inventory.collector import NOT_COLLECTED

ROOT = Path(__file__).resolve().parents[1]
PROPOSAL = (ROOT / "docs" / "proposals" / "conditional-access.md").read_text(encoding="utf-8")


def test_the_proposal_says_design_only_and_cites_learn() -> None:
    assert "**Status: design only, pending review (2026-11-28).**" in PROPOSAL
    assert (
        "https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity"
        in PROPOSAL
    )
    assert "No verdict ever turns to `pass` because of a policy" in PROPOSAL


def test_the_code_is_still_option_a() -> None:
    assert any(n.surface == "conditional-access" for n in NOT_COLLECTED)
    ops = {
        *arm.ARM_OPERATIONS,
        *graph.GRAPH_OPERATIONS,
        *graph.CREDENTIAL_OPERATIONS,
        *graph.FIC_OPERATIONS,
        *graph.MEMBERSHIP_OPERATIONS,
        *graph.PIM_OPERATIONS,
    }
    assert not [op for op in ops if "conditionalAccess" in op]
    for tf in (ROOT / "lab").glob("*.tf"):
        assert "Policy.Read.All" not in tf.read_text(encoding="utf-8"), tf.name
