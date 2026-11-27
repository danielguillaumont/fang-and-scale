"""D-6 and D-7: ``listKeys`` after harden, on both storage accounts (approved 2026-11-27).

Each must be denied. If one ever succeeds, both of that account's keys are
regenerated at once (as SD1), the scout verifies the regeneration, the item fails
and the run exits 1. A denied attempt leaves both accounts' keys exactly as read
before the run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fns.exitcodes import ExitCode
from fns.journal.sqlite import SqliteJournal
from fns.strike.plan import AFTER_HARDEN, PlanError
from fns.strike.strikes import build_plan
from tests.factories import NOW
from tests.scope.writekit import INVOICES_D7, LIST_KEYS, PAYROLL, REGEN_KEY, TARGETS_D7, strike_dict
from tests.strike.faketenant import SCOPE_SHA, Lab, manifest
from tests.strike.test_run import RUN, go, no_secrets

D_ALL: tuple[Any, ...] = ("D-1", "D-2", "D-3", "D-4", "D-5", "D-6", "D-7")


def hardened_lab(**leaky: bool) -> Lab:
    lab = Lab(m=manifest(strike=strike_dict(targets=TARGETS_D7)))
    lab.tenant.hardened = True
    lab.tenant.leaky = {name for name, on in leaky.items() if on}
    return lab


def plan_for(lab: Lab, strikes: tuple[Any, ...] = ("D-6", "D-7")) -> Any:
    return build_plan(strikes, lab.m, SCOPE_SHA, lab.reader(), NOW, run_id=RUN)


def test_d6_and_d7_are_after_harden_attempts() -> None:
    assert AFTER_HARDEN[-2:] == ("D-6", "D-7")


def test_the_plan_lists_keys_on_each_account_with_the_sd1_undo() -> None:
    plan = plan_for(hardened_lab())
    by_key = {w.key: w for w in plan.writes}
    assert sorted(by_key) == ["D-6/list-keys", "D-7/list-keys"]
    for key, account, name in (
        ("D-6/list-keys", PAYROLL, "stpayrolltest"),
        ("D-7/list-keys", INVOICES_D7, "stinvoicesd7"),
    ):
        w = by_key[key]
        assert w.expect == "denied"
        assert (w.request.operation, w.request.method) == (LIST_KEYS, "POST")
        assert w.request.url.split("?")[0].endswith(f"{account}/listKeys")
        assert [(u.operation, u.body) for u in w.undo] == [
            (REGEN_KEY, {"keyName": "key1"}),
            (REGEN_KEY, {"keyName": "key2"}),
        ]
        assert all(u.url.split("?")[0].endswith(f"{account}/regenerateKey") for u in w.undo)
        assert w.observes == (f"resource:{name} listKeys",)
    assert set(plan.pre_state) == {f"arm:{PAYROLL}", f"arm:{INVOICES_D7}"}
    assert all("keyCreationTime" in v for v in plan.pre_state.values())


def test_d7_needs_the_invoices_account_as_a_strike_target() -> None:
    lab = Lab(m=manifest())  # the recorded targets: no invoices account
    lab.tenant.hardened = True
    with pytest.raises(PlanError, match="invoices storage account"):
        plan_for(lab, ("D-7",))


def test_s1_is_unchanged_by_the_new_d_steps() -> None:
    """S1 keeps its plan shape (fixtures/strike-demo replays it)."""
    lab = Lab()
    plan = build_plan(("S1",), lab.m, SCOPE_SHA, lab.reader(), NOW, run_id=RUN)
    (w,) = plan.writes
    assert (w.key, w.expect, w.observes) == ("S1/list-keys", "allowed", ())


def test_denied_attempts_leave_every_key_as_it_was(tmp_path: Path) -> None:
    lab = hardened_lab()
    plan = plan_for(lab, D_ALL)
    before = lab.tenant.snapshot()
    with SqliteJournal(tmp_path / "j.sqlite") as j:
        run = go(lab, plan, j)
    assert run.exit_code == ExitCode.OK and run.verified
    outcomes = {w.key: (w.outcome, w.status, w.undo) for w in run.writes}
    assert outcomes["D-6/list-keys"] == ("denied", 403, [])
    assert outcomes["D-7/list-keys"] == ("denied", 403, [])
    after = lab.tenant.snapshot()
    assert (after["keys"], after["invoice_keys"]) == (before["keys"], before["invoice_keys"])
    keys = {c.what: c for c in run.checks if c.what.startswith("keys ")}
    assert {c.detail for c in keys.values()} == {"unchanged (listKeys not sent)"}
    assert len(keys) == 2 and all(c.ok for c in keys.values())
    assert len(run.checks) == 7  # three apps, two owner lists, two accounts


@pytest.mark.parametrize(
    ("leak", "regenerated", "kept"),
    [
        ("stinvoicesd7", "invoice_keys", "keys"),
        ("stpayrolltest", "keys", "invoice_keys"),
    ],
)
def test_a_succeeding_list_keys_regenerates_both_keys_and_exits_1(
    tmp_path: Path, leak: str, regenerated: str, kept: str
) -> None:
    lab = hardened_lab(**{leak: True})
    plan = plan_for(lab)
    before = lab.tenant.snapshot()
    with SqliteJournal(tmp_path / "j.sqlite") as j:
        run = go(lab, plan, j)
    assert run.exit_code == ExitCode.CONTRACT_FAILED  # 1: the contract fails
    leaked = next(w for w in run.writes if w.outcome == "unexpected-success")
    assert leaked.undo == ["200", "200"]  # key1 and key2 regenerated at once
    after = lab.tenant.snapshot()
    assert all(after[regenerated][k] > before[regenerated][k] for k in ("key1", "key2"))
    assert after[kept] == before[kept]
    details = sorted(c.detail for c in run.checks if c.what.startswith("keys "))
    assert details == ["both regenerated", "unchanged (listKeys not sent)"]
    assert run.verified
    no_secrets(tmp_path / "j.sqlite", lab, run)  # the leaked key values are never kept
