"""M2 C4 regression test: the M2 live run (2026-11-26) recorded as ``fixtures/lab-run-2``.

The live run, signed in as ``sp-fns-scout``, gave these results, and this test pins
them on the sanitized recording plus the contract that lab/contract.tf rendered:

- 12 collectors; 11 complete; ``pim.eligibility`` not-applicable with evidence
  (Graph and ARM eligibility listings both ``400 AadPremiumLicenseRequired``,
  ``/subscribedSkus`` 0 SKUs);
- ``fns contain``: critical reachable 11/0, inconclusive 2/2, exit 1;
- ``fns mutate --harden``: 6/8, survivors exactly the two app-owner mutants;
  hardened baseline 0 failing, 13 inconclusive.

The live digest was ``sha256:68a0208d...``; the replay digest differs because the
IDs are placeholders and the mode is FIXTURE. It is pinned in the golden file.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from fns.contain.evaluate import Evaluation, evaluate
from fns.contain_run import demo_contract
from fns.demo import run_demo_scout
from fns.models.contract import load_contract
from fns.mutate import mutate
from fns.summary import ScoutResult

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "lab"
LAB_RUN = ROOT / "fixtures" / "lab-run-2"
GOLDEN = ROOT / "tests" / "golden"


def _golden(name: str) -> str:
    return (GOLDEN / f"{name}.digest").read_text(encoding="utf-8").strip()


@pytest.fixture(scope="module")
def scout(tmp_path_factory: pytest.TempPathFactory) -> ScoutResult:
    return run_demo_scout(tmp_path_factory.mktemp("lab2"), LAB_RUN)


@pytest.fixture(scope="module")
def lab(scout: ScoutResult) -> Evaluation:
    return evaluate(load_contract(LAB_RUN / "contract.fns.yaml"), scout.snapshot)


def test_replay_is_stable_and_matches_golden(scout: ScoutResult, tmp_path: Path) -> None:
    again = run_demo_scout(tmp_path, LAB_RUN)
    assert scout.digest == again.digest == _golden("lab-run-2")
    snap = scout.snapshot
    assert snap.mode == "FIXTURE"
    assert (len(snap.entities), len(snap.edges), scout.calls) == (211, 32, 34)


def test_collectors_match_the_live_run(scout: ScoutResult) -> None:
    status = {c.name: c.status for c in scout.snapshot.coverage.collectors}
    assert len(status) == 12
    assert status.pop("pim.eligibility") == "not-applicable"
    assert set(status.values()) == {"complete"}
    settings = next(
        c for c in scout.snapshot.coverage.collectors if c.name == "arm.resource-settings"
    )
    assert settings.items == 3


def test_pim_is_not_applicable_with_evidence_from_both_apis(scout: ScoutResult) -> None:
    cov = scout.snapshot.coverage
    assert "pim-eligibility" not in {n.surface for n in cov.not_collected}
    assert "key-vault-access-policies" not in {n.surface for n in cov.not_collected}
    (na,) = cov.not_applicable
    assert na.surface == "pim-eligibility"
    evidence = " | ".join(na.evidence)
    assert "GET /roleManagement/directory/roleEligibilitySchedules -> http-400" in evidence
    assert "ARM roleEligibilitySchedules" in evidence
    assert evidence.count("AadPremiumLicenseRequired") == 2
    assert "GET /subscribedSkus -> ok: 0 SKU(s)" in evidence


EXPECTED = {
    ("resource:kv-crown-tiin02", "secrets/get"): ("fail", "kv-control-to-data"),
    ("resource:kv-crown-tiin02", "secrets/list"): ("fail", "kv-control-to-data"),
    ("resource:stpayrolltiin02", "listKeys"): ("fail", "rbac-action"),
    ("resource:stpayrolltiin02", "blob/read"): ("fail", "listkeys-data"),
    ("resource:stinvoicestiin02", "listKeys"): ("fail", "rbac-action"),
    ("directory:tenant", "roleAssignments/write"): ("fail", "graph-permission"),
    ("directory:tenant", "applications/credentials/update"): ("fail", "owned-object-permission"),
    ("application:id-verifier", "credentials/update"): ("fail", "graph-permission"),
    ("application:id-verifier", "owners/update"): ("fail", "graph-permission"),
    ("application:sp-fns-scout", "credentials/update"): ("fail", "graph-permission"),
    ("application:sp-fns-scout", "owners/update"): ("fail", "graph-permission"),
    ("resource:stinvoicestiin02", "blob/read"): ("inconclusive", "rbac-data-action"),
    ("resource:stinvoicestiin02", "blob/write"): ("inconclusive", "rbac-data-action"),
}


def test_contain_verdicts_match_the_live_run(lab: Evaluation) -> None:
    got = {
        (o.finding.target, o.finding.operation): (o.finding.verdict, o.paths[0].steps[-1].rule)
        for o in lab.outcomes
    }
    assert got == EXPECTED
    assert {o.finding.coverage for o in lab.outcomes} == {"modeled-only"}
    s = lab.summary
    assert (s.critical, s.still_do_failed, s.inconclusive, s.exit_code) == (11, 0, 2, 1)


def test_payroll_blob_read_needs_no_assumed_default(lab: Evaluation) -> None:
    """C1: shared-key access is now collected, so the listKeys hop assumes nothing about it."""
    o = next(
        o
        for o in lab.outcomes
        if (o.finding.target, o.finding.operation) == ("resource:stpayrolltiin02", "blob/read")
    )
    assert not any("not collected" in r for r in o.finding.reasons)


def test_mutation_score_and_survivors_match_the_live_run(scout: ScoutResult) -> None:
    now = datetime(2026, 11, 26, tzinfo=UTC)
    contract = demo_contract(LAB_RUN)
    r = mutate(contract, scout.snapshot, LAB, harden=True, generated_at=now, tool_version="t")
    assert (r.baseline_failures, r.baseline_inconclusive) == (0, 13)
    assert (r.killed, r.total) == (6, 8)
    survivors = sorted(m.id for m in r.mutants if m.outcome == "survived")
    assert survivors == ["app-owner:id-verifier", "app-owner:sp-fns-scout"]
    assert [n.operator for n in r.not_applicable] == ["remove-deny-assignment"]
    assert r.digest() == _golden("lab-run-2-mutate")
