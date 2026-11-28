"""Session D under the lab budget (approved 2026-11-27): exit 0 only if invoices
``blob/write``, ``directory:tenant applications/credentials/update`` and
``directory:tenant roleAssignments/write`` are the only inconclusive items and no
surface is open. Any other inconclusive item is over budget, whatever the count.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fns.contain.evaluate import evaluate
from fns.contain.report import build_report
from fns.models.assertions import AssertionSet, Thresholds
from fns.models.budget import AcceptedInconclusive
from fns.prove.freeze import freeze
from fns.verify import verdict as v
from tests.prove.helpers import lab as m3_lab
from tests.prove.test_option_b import (
    D_STEPS,
    INVOICE_KEYS,
    PAYROLL_KEYS,
    VERIFIER_CRED,
    all_d_steps,
    lab,
    strike,
    verify,
)

__all__ = ["lab"]  # the module-scoped fixture, hardened lab-run-2

ACCEPTED = (
    AcceptedInconclusive(
        target="resource:stinvoicestiin02",
        operation="blob/write",
        reason="writes stay rung 2 by design; prove never makes a write",
    ),
    AcceptedInconclusive(
        target="directory:tenant",
        operation="applications/credentials/update",
        reason="one app's denial isn't tenant-wide",
    ),
    AcceptedInconclusive(
        target="directory:tenant",
        operation="roleAssignments/write",
        reason="SD3, no direct attempt; a strike never counts for it",
    ),
)
THREE = sorted(a.item for a in ACCEPTED)


def budgeted(aset: AssertionSet, **change: Any) -> AssertionSet:
    t = Thresholds(
        max_critical_reachable=0,
        max_inconclusive=3,
        on_inconclusive="fail",
        accepted_inconclusive=ACCEPTED,
    )
    return aset.model_copy(update={"thresholds": t, **change})


def inconclusive(bundle: Any) -> list[str]:
    return sorted(
        f"{f.target} {f.operation}" for f in bundle.findings if f.verdict == "inconclusive"
    )


def test_with_every_d_step_denied_session_d_exits_0(lab: AssertionSet) -> None:
    aset = budgeted(lab)
    bundle = verify(aset, all_d_steps(aset))
    assert inconclusive(bundle) == THREE
    assert (bundle.summary.critical, bundle.summary.exit_code) == (0, 0)
    assert bundle.summary.unaccepted_inconclusive == ()


def test_the_old_budget_still_exits_3(lab: AssertionSet) -> None:
    assert verify(lab, all_d_steps(lab)).summary.exit_code == 3  # max 2, nothing named


@pytest.mark.parametrize("missing", sorted(D_STEPS))
def test_a_missing_d_step_leaves_its_item_unaccepted(lab: AssertionSet, missing: str) -> None:
    aset = budgeted(lab)
    items = D_STEPS[missing][3]
    strikes = [
        strike(aset, key, item) for key, row in D_STEPS.items() if key != missing for item in row[3]
    ]
    bundle = verify(aset, strikes)
    expected = sorted(
        f"{t} {o}"
        for t, o in items
        if (t, o) != ("directory:tenant", "applications/credentials/update")
    )
    if not expected:  # D-1 observes no item
        assert bundle.summary.exit_code == 0
        return
    assert bundle.summary.exit_code == 3
    assert list(bundle.summary.unaccepted_inconclusive) == expected


def test_one_unaccepted_item_fails_even_within_the_count(lab: AssertionSet) -> None:
    """If an accepted item ever resolves, a new inconclusive still fails: the
    count is 3 of 3, but payroll listKeys is not named."""
    aset = budgeted(lab)
    strikes = [s for s in all_d_steps(aset) if s[0].write_key != "D-6/list-keys"]
    findings = list(verify(aset, strikes).findings)
    findings = [
        f.model_copy(update={"verdict": "pass"})
        if (f.target, f.operation) == ("resource:stinvoicestiin02", "blob/write")
        else f
        for f in findings
    ]
    assert sum(f.verdict == "inconclusive" for f in findings) == 3
    s = v.summarize(findings, aset.thresholds)
    assert s.exit_code == 3
    assert s.unaccepted_inconclusive == (" ".join(PAYROLL_KEYS),)


def test_an_open_surface_keeps_session_d_over_budget(lab: AssertionSet) -> None:
    """The PIM precondition: with pim-eligibility open, the application and
    listKeys items stay inconclusive, and none of them is named."""
    opened = tuple(
        a.model_copy(update={"open_surfaces": ("collector:pim.eligibility",)})
        if a.item_kind == "must_not_reach"
        else a
        for a in lab.assertions
    )
    aset = budgeted(lab, assertions=opened)
    bundle = verify(aset, all_d_steps(aset))
    assert bundle.summary.exit_code == 3
    unaccepted = bundle.summary.unaccepted_inconclusive
    assert " ".join(VERIFIER_CRED) in unaccepted and " ".join(INVOICE_KEYS) in unaccepted


def test_freeze_carries_the_named_items(tmp_path: Path) -> None:
    lb = m3_lab(tmp_path)
    budget = lb.contract.budget.model_copy(
        update={
            "max_inconclusive": 3,
            "accepted_inconclusive": (
                AcceptedInconclusive(
                    target="directory:tenant", operation="roleAssignments/write", reason="SD3"
                ),
            ),
        }
    )
    contract = lb.contract.model_validate(
        {**lb.contract.model_dump(), "budget": budget.model_dump()}
    )
    report = build_report(
        evaluate(contract, lb.snapshot), generated_at=lb.snapshot.collected_at, tool_version="t"
    )
    aset = freeze(contract, lb.snapshot, report, frozen_at=lb.snapshot.collected_at)
    assert aset.thresholds.accepted_inconclusive == budget.accepted_inconclusive
    plain = freeze(lb.contract, lb.snapshot, lb.report, frozen_at=lb.snapshot.collected_at)
    assert "accepted_inconclusive" not in plain.canonical_json()
