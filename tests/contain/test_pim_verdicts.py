"""M3 E1: how PIM eligibility, and its absence, reach findings and frozen assertions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from fns.contain.evaluate import evaluate
from fns.contain.report import build_report
from fns.fixtures import wellknown as wk
from fns.inventory.collector import PIM_COLLECTOR, PIM_ELIGIBILITY
from fns.models.contract import Contract
from fns.models.evidence import Finding
from fns.models.snapshot import Snapshot, SnapshotCoverage
from fns.prove.freeze import PIM_ELIGIBLE, freeze
from tests.contain.helpers import AGENT, Snap, contract
from tests.factories import NOW

ITEM = {"resource": "kv-crown", "operations": ["secrets/get"]}
NA = {
    "surface": PIM_ELIGIBILITY,
    "reason": "no subscribed licence carries PIM",
    "evidence": ["GET /roleManagement/directory/roleEligibilitySchedules -> http-400 X"],
}


def _snap(pim: str, **eligible: Any) -> Snap:
    """A world where nothing reaches the vault, every collector is complete, and the
    only open question is PIM: ``pim`` is collected, not-applicable or not-collected."""
    s = Snap()
    s.sp(100, "sp-agent")
    s.kv(enableRbacAuthorization=True)
    status = {"collected": "complete", "not-applicable": "not-applicable"}.get(pim, "failed")
    s.collectors.append({"name": PIM_COLLECTOR, "status": status})
    if pim == "not-applicable":
        s.not_applicable.append(NA)
    elif pim == "not-collected":
        s.missing(PIM_ELIGIBILITY)
    if eligible:
        s.entity(wk.GLOBAL_ADMINISTRATOR, "directoryRole", "Global Administrator")
        s.edge(
            "hasEligibleRole",
            AGENT,
            wk.GLOBAL_ADMINISTRATOR,
            plane="directory",
            role_definition_id=wk.GLOBAL_ADMINISTRATOR,
            directory_scope_id="/",
        )
    return s


def _finding(snapshot: Snapshot, c: Contract) -> Finding:
    (o,) = evaluate(c, snapshot).outcomes
    return o.finding


def _open(snapshot: Snapshot, c: Contract) -> tuple[str, ...]:
    report = build_report(evaluate(c, snapshot), generated_at=NOW, tool_version="test")
    (a,) = freeze(c, snapshot, report, frozen_at=NOW).assertions
    return a.open_surfaces


def test_not_applicable_leaves_nothing_open_so_an_observed_denial_can_pass() -> None:
    c = contract([ITEM])
    snap = _snap("not-applicable").build()
    f = _finding(snap, c)
    # Rung 1 cannot pass on its own (rule 4), but nothing is left open: an observed
    # denial in fns prove is enough.
    assert (f.verdict, f.coverage, f.evidence[0].outcome) == (
        "inconclusive",
        "modeled-only",
        "denied",
    )
    assert _open(snap, c) == ()


def test_not_collected_pim_keeps_the_item_open() -> None:
    c = contract([ITEM])
    snap = _snap("not-collected").build()
    f = _finding(snap, c)
    assert (f.verdict, f.coverage) == ("inconclusive", "not-assessed")
    assert any("pim-eligibility not collected" in r for r in f.reasons)
    assert PIM_ELIGIBILITY in _open(snap, c)


def test_eligibility_of_a_controlled_principal_keeps_every_item_open() -> None:
    c = contract([ITEM])
    snap = _snap("collected", eligible=True).build()
    f = _finding(snap, c)
    assert (f.verdict, f.coverage) == ("inconclusive", "not-assessed")
    assert any("sp-agent is eligible (PIM) for Global Administrator" in r for r in f.reasons), (
        f.reasons
    )
    assert _open(snap, c) == (PIM_ELIGIBLE,)


def test_collected_without_eligibility_is_like_not_applicable() -> None:
    c = contract([ITEM])
    snap = _snap("collected").build()
    assert _finding(snap, c).coverage == "modeled-only"
    assert _open(snap, c) == ()


def test_eligibility_of_someone_else_is_irrelevant() -> None:
    s = _snap("collected")
    other = s.sp(200, "sp-other")
    s.entity(wk.GLOBAL_ADMINISTRATOR, "directoryRole", "Global Administrator")
    s.edge(
        "hasEligibleRole",
        other,
        wk.GLOBAL_ADMINISTRATOR,
        plane="directory",
        role_definition_id=wk.GLOBAL_ADMINISTRATOR,
    )
    assert _finding(s.build(), contract([ITEM])).coverage == "modeled-only"


def test_coverage_rejects_a_surface_in_both_states_and_needs_evidence() -> None:
    with pytest.raises(ValidationError, match="both not collected and not applicable"):
        SnapshotCoverage.model_validate(
            {"not_collected": [{"surface": PIM_ELIGIBILITY, "reason": "x"}], "not_applicable": [NA]}
        )
    with pytest.raises(ValidationError):
        SnapshotCoverage.model_validate({"not_applicable": [{**NA, "evidence": []}]})


def test_empty_not_applicable_is_left_out_of_the_canonical_form() -> None:
    """Snapshots recorded before E1 keep their digests."""
    assert "not_applicable" not in SnapshotCoverage().canonical_json()
    assert (
        "not_applicable"
        in SnapshotCoverage.model_validate({"not_applicable": [NA]}).canonical_json()
    )


def test_scout_summary_prints_the_evidence(tmp_path: Path) -> None:
    from io import StringIO

    from rich.console import Console

    from fns.console import THEME
    from fns.summary import ScoutResult, render_summary

    buf = StringIO()
    snap = _snap("not-applicable").build()
    result = ScoutResult(snap, snap.digest(), tmp_path / "s.json", tmp_path / "j", "run", 0)
    render_summary(result, Console(file=buf, width=200, color_system=None, theme=THEME))
    out = buf.getvalue()
    assert "not applicable in this tenant (evidence):" in out
    assert "pim-eligibility: no subscribed licence carries PIM" in out
    assert "roleEligibilitySchedules -> http-400 X" in out
    assert "not-applicable" in out  # the collector row
