"""S4's token claims are a safety stop, never verdict evidence (approved 2026-11-27).

The claims are read without verifying the token's signature. That is acceptable
only because the answer decides whether S4 may go on, and nothing else. These
tests pin it:

- ``strike-run.json`` carries no claim and no safety-stop result;
- S4's planned writes observe no contract item, and ``fns prove --after-strike``
  counts no before-harden write, even from a plan forged to look like evidence;
- neither the prover nor the verifier reads the claims or the safety stop.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fns.models.assertions import AssertionSet
from fns.prove.strikes import load_after_strike
from fns.scope.writes import CAPABILITY_ROLE
from fns.strike.plan import StrikePlan
from fns.strike.strikes import ASSIGN_KEY, TOKEN_KEY
from tests.prove.baseline import GOLDENS, run
from tests.prove.test_after_strike import AT, _assertions
from tests.scope.writekit import SP_ESC
from tests.strike.faketenant import Lab, MemoryStrikeJournal
from tests.strike.test_s4 import RUN, go, plan_for

SRC = Path(__file__).resolve().parents[2] / "src" / "fns"


@pytest.fixture(scope="module")
def aset(tmp_path_factory: pytest.TempPathFactory) -> AssertionSet:
    out = tmp_path_factory.mktemp("s4-base")
    run(GOLDENS[sorted(GOLDENS)[0]], out)
    return _assertions(out)


def test_the_run_record_carries_no_claim_and_no_safety_stop() -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    plan = plan_for(lab)
    result = go(lab, plan, journal)
    record = json.dumps(result.to_dict())
    for word in ("claims", "roles", "safety_stop", "proof", '"oid"', CAPABILITY_ROLE):
        assert word not in record, word
    # the journal keeps them for the operator, and only there
    rows = [d for k, ph, d in journal.strike_events(RUN) if k == TOKEN_KEY and ph == "result"]
    assert rows and rows[0]["safety_stop"] == "passed"


def test_s4s_writes_observe_nothing() -> None:
    plan = plan_for(Lab())
    for w in plan.writes:
        if w.strike == "S4":
            assert w.expect == "allowed" and w.observes == (), w.key


def _forged_s4(where: Path, aset: AssertionSet, strike: str) -> Path:
    """A self-consistent plan and run that dress an S4 write up as a denied attempt."""
    item = next(a for a in aset.assertions if a.item_kind == "must_not_reach")
    key = ASSIGN_KEY if strike == "S4" else "D-2/item-0"
    writes: list[dict[str, Any]] = [
        {
            "key": key,
            "strike": strike,
            "request": {
                "operation": "graph:POST /servicePrincipals/{id}/appRoleAssignedTo",
                "method": "POST",
                "url": f"https://graph.microsoft.com/v1.0/servicePrincipals/{SP_ESC}/appRoleAssignedTo",
            },
            "expect": "denied",
            "observes": [f"{item.target} {item.operation}"],
        }
    ]
    plan = StrikePlan.model_validate(
        {
            "run_id": "202611271200-forged",
            "tenant_id": str(aset.tenant_id).lower(),
            "scope_sha256": "a" * 64,
            "agent_object_id": "00000000-0000-4000-8000-000000000100",
            "created_at": AT.isoformat(),
            "expires_at": AT.replace(hour=13).isoformat(),
            "strikes": [strike],
            "targets": {},
            "pre_state": {},
            "writes": writes,
        }
    )
    where.mkdir(parents=True, exist_ok=True)
    (where / "plan.json").write_text(plan.canonical_json())
    record = {
        "mode": aset.mode,
        "run_id": plan.run_id,
        "plan_hash": f"sha256:{plan.plan_hash()}",
        "writes": [
            {
                "key": key,
                "strike": strike,
                "expect": "denied",
                "outcome": "denied",
                "status": 403,
                "undo": [],
                "observes": writes[0]["observes"],
            }
        ],
        "verification": [],
        "exit_code": 0,
    }
    (where / "strike-run.json").write_text(json.dumps(record))
    return where


def test_a_forged_s4_write_is_never_counted(tmp_path: Path, aset: AssertionSet) -> None:
    assert load_after_strike(_forged_s4(tmp_path / "s4", aset, "S4"), aset) == []
    # the same write as an after-harden attempt is counted: the strike is what drops it
    assert len(load_after_strike(_forged_s4(tmp_path / "d2", aset, "D-2"), aset)) == 1


@pytest.mark.parametrize("package", ["prove", "verify"])
def test_neither_prover_nor_verifier_reads_the_claims(package: str) -> None:
    for path in sorted((SRC / package).rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for word in ("safety_stop", "token_proof", "recorded_claims", "fns.strike.run"):
            assert word not in text, (path.name, word)
        assert CAPABILITY_ROLE not in text, path.name
