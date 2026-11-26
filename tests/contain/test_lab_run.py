"""The seeded contract against the first recorded lab run (FIXTURE evidence).

These are the expected M2 verdicts from docs/milestones/M2.md, C4, computed
from real (sanitized) ARM and Graph responses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fns.contain.evaluate import Evaluation, evaluate
from fns.demo import run_demo_scout
from fns.models.contract import load_contract

ROOT = Path(__file__).resolve().parents[2]
LAB_RUN = ROOT / "fixtures" / "lab-run-1"


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Evaluation:
    snapshot = run_demo_scout(tmp_path_factory.mktemp("lab"), LAB_RUN).snapshot
    return evaluate(load_contract(LAB_RUN / "contract.fns.yaml"), snapshot)


EXPECTED = {
    ("resource:kv-crown-tiin02", "secrets/get"): ("fail", "kv-control-to-data"),
    ("resource:kv-crown-tiin02", "secrets/list"): ("fail", "kv-control-to-data"),
    ("resource:stpayrolltiin02", "listKeys"): ("fail", "rbac-action"),
    ("resource:stpayrolltiin02", "blob/read"): ("fail", "listkeys-data"),
    ("directory:tenant", "roleAssignments/write"): ("fail", "graph-permission"),
    ("directory:tenant", "applications/credentials/update"): ("fail", "owned-object-permission"),
    ("resource:stinvoicestiin02", "listKeys"): ("fail", "rbac-action"),
    # Contract v2: through the self-grant chain, Application.ReadWrite.All reaches both apps.
    ("application:id-verifier", "credentials/update"): ("fail", "graph-permission"),
    ("application:id-verifier", "owners/update"): ("fail", "graph-permission"),
    ("application:sp-fns-scout", "credentials/update"): ("fail", "graph-permission"),
    ("application:sp-fns-scout", "owners/update"): ("fail", "graph-permission"),
    ("resource:stinvoicestiin02", "blob/read"): ("inconclusive", "rbac-data-action"),
    ("resource:stinvoicestiin02", "blob/write"): ("inconclusive", "rbac-data-action"),
}


def test_seeded_contract_verdicts(lab: Evaluation) -> None:
    got = {
        (o.finding.target, o.finding.operation): (o.finding.verdict, o.paths[0].steps[-1].rule)
        for o in lab.outcomes
    }
    assert got == EXPECTED
    assert {o.finding.coverage for o in lab.outcomes} == {"modeled-only"}


def test_seeded_contract_fails_with_exit_1(lab: Evaluation) -> None:
    s = lab.summary
    assert (s.critical, s.still_do_failed, s.inconclusive, s.exit_code) == (11, 0, 2, 1)
    assert lab.snapshot.mode == "FIXTURE"


def test_tenant_escalation_goes_through_the_escalation_target(lab: Evaluation) -> None:
    ra = next(o for o in lab.outcomes if o.finding.operation == "roleAssignments/write")
    text = " | ".join(s.text for s in ra.paths[0].steps)
    assert "owns app-escalation-target" in text
    assert "AppRoleAssignment.ReadWrite.All" in text
    assert "RoleManagement.ReadWrite.Directory" in text


def test_scout_identity_has_no_reach(tmp_path: Path) -> None:
    """sp-fns-scout is read-only: nothing in the seeded contract is reachable."""
    snapshot = run_demo_scout(tmp_path, LAB_RUN).snapshot
    c = load_contract(LAB_RUN / "contract.fns.yaml").model_copy(
        update={"assume_compromised": "sp:sp-fns-scout"}
    )
    ev = evaluate(c, snapshot)
    must_not = [o.finding for o in ev.outcomes if o.finding.item_kind == "must_not_reach"]
    assert {f.verdict for f in must_not} == {"inconclusive"}
