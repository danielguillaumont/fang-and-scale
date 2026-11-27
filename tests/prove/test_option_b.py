"""Option B: a LIVE after-harden strike denial counts like an observed probe denial
(approved 2026-11-27, ``docs/milestones/M4-exit-gate-plan.md``).

A strike is a *counting denial* only if it is LIVE, D-2 to D-5, a 403, on the
item's exact operation and exact object, and not on ``roleAssignments/write``.
It fills the observed-denial slot of the probe rules, so ``pass`` still needs
every path refuted and no open surface. Everything else stays context, or fails
the finding. The tests:

- the LIVE matrix: lab-run-2, hardened in the model, with D-2 to D-5 denied;
- one negative row per condition, each starting from the matrix;
- the PIM precondition (approved 2026-11-27): ``pim-eligibility`` is closed only
  when its collector ran and was complete, or not applicable with evidence;
- the guardrail: no finding loosens without a counting denial (a property over
  every assertion and any strike observation), and a forced breach raises.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from fns.contain import semantics as sem
from fns.contain_run import run_demo_contain
from fns.models.assertions import (
    PROBE_RUNG,
    Assertion,
    AssertionSet,
    PathAssertion,
    ProbeObservation,
    StrikeObservation,
)
from fns.models.evidence import Finding
from fns.models.snapshot import CollectorRun, NotApplicable, NotCollected, Snapshot
from fns.prove.freeze import _open_surfaces
from fns.verify import verdict as v
from fns.verify.inputs import Inputs
from fns.verify.main import build
from tests.prove.baseline import GOLDENS, run

AT = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
LAB_RUN = Path(__file__).resolve().parents[2] / "fixtures" / "lab-run-2"
ADD_PASSWORD = "graph:POST /applications/{id}/addPassword"  # noqa: S105
ADD_OWNER = "graph:POST /applications/{id}/owners/$ref"
OTHER_OBJECT = "00000000-0000-4000-8000-00000000beef"

VERIFIER_CRED = ("application:id-verifier", "credentials/update")
SCOUT_CRED = ("application:sp-fns-scout", "credentials/update")
VERIFIER_OWNERS = ("application:id-verifier", "owners/update")
SCOUT_OWNERS = ("application:sp-fns-scout", "owners/update")
TENANT_CRED = ("directory:tenant", "applications/credentials/update")
ROLE_WRITE = ("directory:tenant", "roleAssignments/write")
PAYROLL_KEYS = ("resource:stpayrolltiin02", "listKeys")
INVOICE_KEYS = ("resource:stinvoicestiin02", "listKeys")
LIST_KEYS = "arm:Microsoft.Storage/storageAccounts/listKeys/action"

D_STEPS = {
    # write key, strike, request, the items its plan row observes (strikes.OBSERVES)
    "D-2/add-password": ("D-2", ADD_PASSWORD, VERIFIER_CRED, [VERIFIER_CRED, TENANT_CRED]),
    "D-3/add-password": ("D-3", ADD_PASSWORD, SCOUT_CRED, [SCOUT_CRED]),
    "D-4/add-owner": ("D-4", ADD_OWNER, VERIFIER_OWNERS, [VERIFIER_OWNERS]),
    "D-5/add-owner": ("D-5", ADD_OWNER, SCOUT_OWNERS, [SCOUT_OWNERS]),
    "D-6/list-keys": ("D-6", LIST_KEYS, PAYROLL_KEYS, [PAYROLL_KEYS]),  # approved 2026-11-27
    "D-7/list-keys": ("D-7", LIST_KEYS, INVOICE_KEYS, [INVOICE_KEYS]),
}


# --- the hardened LIVE lab --------------------------------------------------------------


def _harden(a: Assertion) -> Assertion:
    """What the model says after harden: nothing reachable, no path."""
    if a.item_kind != "must_not_reach":
        return a
    return a.model_copy(
        update={
            "modeled_outcome": "denied",
            "modeled_reasons": ("not reachable in the model after harden",),
            "paths": (),
        }
    )


def _probe_result(a: Assertion, kind: str) -> tuple[str, int | None]:
    """The live probes after harden: forbidden reads denied, legitimate use allowed."""
    if a.item_kind == "must_still_do":
        return "allowed", 200 if kind == "data-read" else None
    return "denied", 403 if kind == "data-read" else None


def _observations(aset: AssertionSet) -> dict[str, tuple[ProbeObservation, str]]:
    out = {}
    for a in aset.assertions:
        for p in a.probes:
            if p.purpose != "direct":
                continue
            outcome, status = _probe_result(a, p.kind)
            o = ProbeObservation(
                version=1,
                mode="LIVE",
                probe_id=p.id,
                finding_id=a.finding_id,
                kind=p.kind,
                rung=PROBE_RUNG[p.kind],
                outcome=outcome,  # type: ignore[arg-type]
                detail="synthetic: after harden",
                http_status=status,
                observed_at=AT,
            )
            out[p.id] = (o, hashlib.sha256(o.file_bytes()).hexdigest())
    return out


@pytest.fixture(scope="module")
def lab() -> AssertionSet:
    with tempfile.TemporaryDirectory() as tmp:
        run(GOLDENS["lab-run-2-prove"], Path(tmp))
        (path,) = Path(tmp).rglob("assertions.json")
        aset = AssertionSet.model_validate_json(path.read_bytes())
    hardened = tuple(_harden(a) for a in aset.assertions)
    return aset.model_copy(update={"mode": "LIVE", "assertions": hardened})


def _item(aset: AssertionSet, item: tuple[str, str]) -> Assertion:
    (a,) = [a for a in aset.assertions if (a.target, a.operation) == item]
    return a


def strike(
    aset: AssertionSet, key: str, item: tuple[str, str], **change: Any
) -> tuple[StrikeObservation, str]:
    """One D-step observation for ``item``, as ``fns prove --after-strike`` writes it."""
    name, request, aimed_at, _ = D_STEPS[key]
    fields: dict[str, Any] = {
        "version": 1,
        "mode": "LIVE",
        "strike_run_id": "202611271200-optionb",
        "plan_sha256": "b" * 64,
        "write_key": key,
        "strike": name,
        "target": item[0],
        "operation": item[1],
        "outcome": "denied",
        "http_status": 403,
        "observed_at": AT,
        "request_operation": request,
        "request_object_id": _item(aset, aimed_at).target_object_id,
    }
    fields.update(change)
    o = StrikeObservation.model_validate(fields)
    return o, hashlib.sha256(o.file_bytes()).hexdigest()


def all_d_steps(aset: AssertionSet) -> list[tuple[StrikeObservation, str]]:
    return [strike(aset, key, item) for key, row in D_STEPS.items() for item in row[3]]


def verify(aset: AssertionSet, strikes: list[tuple[StrikeObservation, str]]) -> Any:
    inputs = Inputs(
        run_dir=Path("unused"),
        assertions=aset,
        assertions_digest="c" * 64,
        observations=_observations(aset),
        unfinished=(),
        strikes=tuple(strikes),
    )
    bundle, _ = build(inputs, identity="test", now=AT)
    return bundle


def by_item(bundle: Any) -> dict[tuple[str, str], Finding]:
    return {(f.target, f.operation): f for f in bundle.findings}


def strike_roles(f: Finding) -> list[str | None]:
    return [e.role for e in f.evidence if e.source == v.STRIKE_SOURCE]


# --- the matrix ---------------------------------------------------------------------------


def test_the_frozen_application_items_carry_their_object_ids(lab: AssertionSet) -> None:
    for item in (VERIFIER_CRED, SCOUT_CRED, VERIFIER_OWNERS, SCOUT_OWNERS):
        assert _item(lab, item).target_object_id is not None
    assert (
        _item(lab, VERIFIER_CRED).target_object_id == _item(lab, VERIFIER_OWNERS).target_object_id
    )
    assert _item(lab, VERIFIER_CRED).target_object_id != _item(lab, SCOUT_CRED).target_object_id
    for item in (TENANT_CRED, ROLE_WRITE):
        assert _item(lab, item).target_object_id is None
    for item in (PAYROLL_KEYS, INVOICE_KEYS):  # a resource's normalized ARM ID
        oid = _item(lab, item).target_object_id
        assert oid is not None and oid.startswith("/subscriptions/")
        assert oid.endswith("/storageaccounts/" + item[0].removeprefix("resource:"))


MATRIX = {
    # item: (verdict without strikes, verdict with D-2 to D-7 denied)
    PAYROLL_KEYS: ("inconclusive", "pass"),  # D-6
    INVOICE_KEYS: ("inconclusive", "pass"),  # D-7
    VERIFIER_CRED: ("inconclusive", "pass"),
    SCOUT_CRED: ("inconclusive", "pass"),
    VERIFIER_OWNERS: ("inconclusive", "pass"),
    SCOUT_OWNERS: ("inconclusive", "pass"),
    TENANT_CRED: ("inconclusive", "inconclusive"),  # one app is not every app
    ROLE_WRITE: ("inconclusive", "inconclusive"),  # SD3
}


def test_the_live_matrix(lab: AssertionSet) -> None:
    before = by_item(verify(lab, []))
    after_bundle = verify(lab, all_d_steps(lab))
    after = by_item(after_bundle)
    for item, (old, new) in MATRIX.items():
        assert (before[item].verdict, after[item].verdict) == (old, new), item
    for item in (
        VERIFIER_CRED,
        SCOUT_CRED,
        VERIFIER_OWNERS,
        SCOUT_OWNERS,
        PAYROLL_KEYS,
        INVOICE_KEYS,
    ):
        f = after[item]
        assert f.coverage == "verified"
        assert strike_roles(f) == [None]  # supporting evidence
        assert f.reasons[0].startswith("denied by an after-harden strike (D-")
        assert f.reasons[0].endswith("(observed), and every modeled path is refuted")
    assert strike_roles(after[TENANT_CRED]) == ["context"]
    assert strike_roles(after[ROLE_WRITE]) == []
    assert before[VERIFIER_CRED].coverage == "modeled-only"


def test_the_rest_of_the_contract_after_harden(lab: AssertionSet) -> None:
    """Items no D-step observes are as before. With D-6 and D-7, three items stay
    inconclusive: blob/write (no observed success), the tenant-wide item and SD3.
    Over the old budget of 2 that is exit 3 (the lab contract budget is raised to 3 separately)."""
    after_bundle = verify(lab, all_d_steps(lab))
    after = by_item(after_bundle)
    expect = {
        ("resource:kv-crown-tiin02", "secrets/get"): "pass",
        ("resource:kv-crown-tiin02", "secrets/list"): "pass",
        ("resource:stpayrolltiin02", "blob/read"): "pass",
        ("resource:stpayrolltiin02", "listKeys"): "pass",
        ("resource:stinvoicestiin02", "listKeys"): "pass",
        ("resource:stinvoicestiin02", "blob/read"): "pass",
        ("resource:stinvoicestiin02", "blob/write"): "inconclusive",
    }
    assert {k: after[k].verdict for k in expect} == expect
    assert after_bundle.summary.inconclusive == 3  # 9 without option B
    assert verify(lab, []).summary.inconclusive == 9
    assert (after_bundle.summary.critical, after_bundle.summary.exit_code) == (0, 3)


# --- one negative row per condition -------------------------------------------------------


def _row(
    change: dict[str, Any] | None = None,
    item: tuple[str, str] = VERIFIER_CRED,
    key: str = "D-2/add-password",
    assertion: dict[str, Any] | None = None,
    live: bool = True,
) -> Callable[[AssertionSet], tuple[Assertion, tuple[StrikeObservation, str], bool]]:
    def make(lab: AssertionSet) -> tuple[Assertion, tuple[StrikeObservation, str], bool]:
        a = _item(lab, item).model_copy(update=assertion or {})
        return a, strike(lab, key, item, **(change or {})), live

    return make


NOT_COUNTING = {
    "fixture-run": (_row(live=False), "not LIVE: FIXTURE never counts"),
    "fixture-observation": (_row({"mode": "FIXTURE"}), "not LIVE: FIXTURE never counts"),
    "D-1": (_row({"strike": "D-1"}), "D-1 does not make that request"),
    "D-4-on-credentials": (_row({"strike": "D-4"}), "D-4 does not make that request"),
    "401": (_row({"http_status": 401}), "HTTP 401, not 403"),
    "400": (_row({"http_status": 400}), "HTTP 400, not 403"),
    "404": (_row({"http_status": 404}), "HTTP 404, not 403"),
    "no-status": (_row({"http_status": None}), "HTTP None, not 403"),
    "owners-request": (_row({"request_operation": ADD_OWNER}), "not the item's exact operation"),
    "other-request": (
        _row({"request_operation": "graph:POST /applications/{id}/removePassword"}),
        "not a write in the exact-operation table",
    ),
    "old-artifact-operation": (
        _row({"request_operation": None}),
        "not a write in the exact-operation table",
    ),
    "old-artifact-object": (_row({"request_object_id": None}), "not the item's exact object"),
    "other-object": (_row({"request_object_id": OTHER_OBJECT}), "not the item's exact object"),
    "unresolved-target": (
        _row(assertion={"target_object_id": None}),
        "not the item's exact object",
    ),
    "tenant-wide": (_row(item=TENANT_CRED), "not the item's exact operation"),
    "role-assignments": (_row(item=ROLE_WRITE), "roleAssignments/write never counts (SD3)"),
    # listKeys (D-6, D-7)
    "list-keys-401": (
        _row({"http_status": 401}, item=PAYROLL_KEYS, key="D-6/list-keys"),
        "HTTP 401, not 403",
    ),
    "list-keys-fixture": (
        _row(item=PAYROLL_KEYS, key="D-6/list-keys", live=False),
        "not LIVE: FIXTURE never counts",
    ),
    "list-keys-other-account": (
        _row(
            {"request_object_id": "/subscriptions/00000000-0000-4000-8000-000000000001/x"},
            item=PAYROLL_KEYS,
            key="D-6/list-keys",
        ),
        "not the item's exact object",
    ),
    "list-keys-by-d2": (
        _row({"strike": "D-2"}, item=PAYROLL_KEYS, key="D-6/list-keys"),
        "D-2 does not make that request",
    ),
    "list-keys-by-s1-key": (
        _row(
            {"request_operation": "arm:Microsoft.Storage/storageAccounts/regenerateKey/action"},
            item=PAYROLL_KEYS,
            key="D-6/list-keys",
        ),
        "not a write in the exact-operation table",
    ),
    "list-keys-on-blob-read": (
        _row(item=("resource:stpayrolltiin02", "blob/read"), key="D-6/list-keys"),
        "not the item's exact operation",
    ),
    "add-password-on-list-keys": (
        _row(item=PAYROLL_KEYS, key="D-2/add-password"),
        "not the item's exact operation",
    ),
}


@pytest.mark.parametrize("name", sorted(NOT_COUNTING))
def test_a_strike_that_breaks_one_condition_settles_nothing(name: str, lab: AssertionSet) -> None:
    make, why = NOT_COUNTING[name]
    a, s, live = make(lab)
    assert v.not_counting(s[0], a, live=live) == why
    obs = {pid: o for pid, o in _observations(lab).items() if any(p.id == pid for p in a.probes)}
    baseline = v.judge(a, obs, lab.contract)
    f = v.judge_with_strikes(a, obs, lab.contract, [s], live=live)
    assert (f.verdict, f.coverage, f.gap, f.reasons) == (
        baseline.verdict,
        baseline.coverage,
        baseline.gap,
        baseline.reasons,
    )
    assert strike_roles(f) == ["context"]


def test_another_items_strike_never_counts(lab: AssertionSet) -> None:
    a = _item(lab, VERIFIER_CRED)
    s = strike(lab, "D-4/add-owner", VERIFIER_OWNERS)
    assert v.not_counting(s[0], a, live=True) == "observes another item"


def test_a_must_still_do_item_is_never_passed_by_a_denial(lab: AssertionSet) -> None:
    a = _item(lab, ("resource:stinvoicestiin02", "blob/write"))
    s = strike(lab, "D-2/add-password", (a.target, a.operation))
    assert v.not_counting(s[0], a, live=True) == "not a must_not_reach item"


def test_an_open_surface_keeps_a_counting_denial_inconclusive(lab: AssertionSet) -> None:
    a = _item(lab, VERIFIER_CRED).model_copy(update={"open_surfaces": ("pim-eligibility",)})
    f = v.judge_with_strikes(
        a, {}, lab.contract, [strike(lab, "D-2/add-password", VERIFIER_CRED)], live=True
    )
    assert f.verdict == "inconclusive"
    assert (
        f.reasons[0] == "denied by an after-harden strike (D-2), but not collected: pim-eligibility"
    )
    assert f.coverage == "verified"


def test_an_unrefuted_path_keeps_the_item_failing(lab: AssertionSet) -> None:
    path = PathAssertion(path_id="a" * 64, summary="assume-compromised -> owner", refuted_by=())
    a = _item(lab, VERIFIER_CRED).model_copy(
        update={"modeled_outcome": "allowed", "paths": (path,)}
    )
    f = v.judge_with_strikes(
        a, {}, lab.contract, [strike(lab, "D-2/add-password", VERIFIER_CRED)], live=True
    )
    assert f.verdict == "fail"
    assert f.reasons[0] == (
        "the operation itself was denied by an after-harden strike (D-2), "
        "but escalation paths remain"
    )
    assert strike_roles(f) == ["context"]


def test_a_probe_success_beats_a_counting_denial(lab: AssertionSet) -> None:
    a = _item(lab, ("resource:kv-crown-tiin02", "secrets/get"))
    obs = {pid: o for pid, o in _observations(lab).items() if any(p.id == pid for p in a.probes)}
    (pid,) = [p.id for p in a.probes if p.purpose == "direct" and p.kind == "data-read"]
    allowed = obs[pid][0].model_copy(update={"outcome": "allowed", "http_status": 200})
    obs[pid] = (allowed, obs[pid][1])
    counting = [strike(lab, "D-2/add-password", (a.target, a.operation))]
    assert v.judge(a, obs, lab.contract, counting).verdict == "fail"


def test_a_strike_success_fails_the_item_even_beside_a_denial(lab: AssertionSet) -> None:
    a = _item(lab, VERIFIER_CRED)
    denied = strike(lab, "D-2/add-password", VERIFIER_CRED)
    allowed = strike(
        lab, "D-2/add-password", VERIFIER_CRED, outcome="allowed", http_status=200, observed_at=AT
    )
    allowed = (allowed[0].model_copy(update={"write_key": "D-2/again"}), "d" * 64)
    f = v.judge_with_strikes(a, {}, lab.contract, [denied, allowed], live=True)
    assert f.verdict == "fail"
    assert f.reasons[0].startswith("an after-harden strike attempt succeeded")


@pytest.mark.parametrize(
    ("key", "item"), [("D-6/list-keys", PAYROLL_KEYS), ("D-7/list-keys", INVOICE_KEYS)]
)
def test_a_list_keys_that_succeeds_after_harden_fails_its_item(
    lab: AssertionSet, key: str, item: tuple[str, str]
) -> None:
    """If D-6 or D-7 ever succeeds, the item fails (the run regenerates both keys
    and exits 1; tests/strike/test_listkeys_d_steps.py)."""
    a = _item(lab, item)
    obs = {pid: o for pid, o in _observations(lab).items() if any(p.id == pid for p in a.probes)}
    allowed = strike(lab, key, item, outcome="allowed", http_status=200, observed_at=AT)
    f = v.judge_with_strikes(a, obs, lab.contract, [allowed], live=True)
    assert f.verdict == "fail"
    assert f.reasons[0].startswith("an after-harden strike attempt succeeded")
    with_other = verify(lab, [*all_d_steps(lab)])
    assert by_item(with_other)[item].verdict == "pass"  # the denial alone passes it


# --- the PIM precondition for session D (approved 2026-11-27) ----------------------------


@pytest.fixture(scope="module")
def snapshot() -> Iterator[Snapshot]:
    with tempfile.TemporaryDirectory() as tmp:
        scout, _ = run_demo_contain(Path(tmp), LAB_RUN)
        yield scout.snapshot


def _pim(snapshot: Snapshot, state: str) -> Snapshot:
    c = snapshot.coverage
    others = [r for r in c.collectors if r.name != "pim.eligibility"]
    not_applicable = [n for n in c.not_applicable if n.surface != "pim-eligibility"]
    na = [n for n in c.not_applicable if n.surface == "pim-eligibility"]
    missing = NotCollected(surface="pim-eligibility", reason="synthetic")
    collectors, not_collected = list(c.collectors), list(c.not_collected)
    if state == "complete":
        collectors = [*others, CollectorRun(name="pim.eligibility", status="complete")]
        cov = c.model_copy(
            update={"collectors": tuple(collectors), "not_applicable": tuple(not_applicable)}
        )
    elif state == "not-applicable-with-evidence":
        assert na and na[0].evidence  # lab-run-2 as recorded
        cov = c
    elif state == "did-not-run":
        cov = c.model_copy(
            update={
                "collectors": tuple(others),
                "not_applicable": tuple(not_applicable),
                "not_collected": (*not_collected, missing),
            }
        )
    else:  # "failed" or "partial": the collector errored
        collectors = [
            *others,
            CollectorRun(
                name="pim.eligibility",
                status="failed" if state == "failed" else "partial",
                error_codes=("http-403",),
            ),
        ]
        cov = c.model_copy(
            update={
                "collectors": tuple(collectors),
                "not_applicable": tuple(not_applicable),
                "not_collected": (*not_collected, missing),
            }
        )
    return snapshot.model_copy(update={"coverage": cov})


PIM = {
    "complete": ((), "pass"),
    "not-applicable-with-evidence": ((), "pass"),
    "did-not-run": (("pim-eligibility",), "inconclusive"),
    "failed": (("collector:pim.eligibility", "pim-eligibility"), "inconclusive"),
    "partial": (("collector:pim.eligibility", "pim-eligibility"), "inconclusive"),
}


@pytest.mark.parametrize("state", sorted(PIM))
def test_pim_must_be_complete_or_not_applicable_with_evidence(
    state: str, snapshot: Snapshot, lab: AssertionSet
) -> None:
    surfaces, verdict = PIM[state]
    semantics = sem.lookup("application", "credentials/update")
    open_ = _open_surfaces(_pim(snapshot, state), semantics, None)
    assert open_ == surfaces
    a = _item(lab, VERIFIER_CRED).model_copy(update={"open_surfaces": open_})
    f = v.judge_with_strikes(
        a, {}, lab.contract, [strike(lab, "D-2/add-password", VERIFIER_CRED)], live=True
    )
    assert f.verdict == verdict
    if verdict == "inconclusive":
        assert f.reasons[0].endswith("but not collected: " + ", ".join(surfaces))


def test_not_applicable_needs_its_evidence() -> None:
    with pytest.raises(ValidationError):
        NotApplicable(surface="pim-eligibility", reason="no P2 licence", evidence=())


# --- the guardrail ----------------------------------------------------------------------


def test_a_forced_breach_raises(lab: AssertionSet, monkeypatch: pytest.MonkeyPatch) -> None:
    """If anything let a non-counting denial into the slot, the re-check catches it."""
    a = _item(lab, VERIFIER_CRED)
    fixture_denial = strike(lab, "D-2/add-password", VERIFIER_CRED, mode="FIXTURE")
    monkeypatch.setattr(v, "counting_denials", lambda a, s, live: list(s))
    with pytest.raises(v.GuardrailError, match="without a counting denial"):
        v.judge_with_strikes(a, {}, lab.contract, [fixture_denial], live=True)


DRAW = st.fixed_dictionaries(
    {
        "key": st.sampled_from(sorted(D_STEPS)),
        "strike": st.sampled_from(["D-1", "D-2", "D-3", "D-4", "D-5", "D-6", "D-7"]),
        "mode": st.sampled_from(["LIVE", "FIXTURE"]),
        "outcome": st.sampled_from(["allowed", "denied"]),
        "http_status": st.sampled_from([200, 201, 204, 400, 401, 403, 404, None]),
        "request_operation": st.sampled_from(
            [ADD_PASSWORD, ADD_OWNER, LIST_KEYS, "graph:GET /x", None]
        ),
        "object": st.sampled_from(["own", "other", "none"]),
    }
)


@settings(
    max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    index=st.integers(min_value=0, max_value=10_000),
    draws=st.lists(DRAW, max_size=4),
    live=st.booleans(),
)
def test_no_finding_loosens_without_a_counting_denial(
    lab: AssertionSet, index: int, draws: list[dict[str, Any]], live: bool
) -> None:
    a = lab.assertions[index % len(lab.assertions)]
    obs = {pid: o for pid, o in _observations(lab).items() if any(p.id == pid for p in a.probes)}
    strikes = []
    for n, d in enumerate(draws):
        obj = {"own": a.target_object_id, "other": OTHER_OBJECT, "none": None}[d["object"]]
        o, _ = strike(
            lab,
            d["key"],
            (a.target, a.operation),
            strike=d["strike"],
            mode=d["mode"],
            outcome=d["outcome"],
            http_status=d["http_status"],
            request_operation=d["request_operation"],
            request_object_id=obj,
        )
        strikes.append(
            (
                o.model_copy(update={"write_key": f"{d['key'].split('/')[0]}/n{n}"}),
                f"{n}".ljust(64, "e"),
            )
        )
    baseline = v.judge(a, obs, lab.contract)
    new = v.judge_with_strikes(a, obs, lab.contract, strikes, live=live)
    counting = [s for s in strikes if v.not_counting(s[0], a, live=live) is None]

    # Evidence only grows, and only by strike evidence.
    kept = list(new.evidence)
    for e in baseline.evidence:
        kept.remove(e)
    assert all(e.source == v.STRIKE_SOURCE for e in kept)
    assert len(kept) == len(strikes)

    if v.VERDICT_RANK[new.verdict] > v.VERDICT_RANK[baseline.verdict]:
        assert counting
        assert new.verdict == "pass" and not a.open_surfaces
        assert not any(o.outcome == "allowed" for o, _ in strikes)
        kinds = {v.COUNTING[str(o.request_operation)][2] for o, _ in counting}
        assert kinds == {a.target.partition(":")[0]}
        assert {v.COUNTING[str(o.request_operation)][0] for o, _ in counting} == {a.operation}
        assert (a.target, a.operation) not in v.NEVER_COUNTS
    if not counting:
        assert new == v.with_strikes(baseline, strikes)
    if a.item_kind == "must_not_reach" and any(o.outcome == "allowed" for o, _ in strikes):
        assert new.verdict == "fail"


def test_the_verifier_isolation_holds() -> None:
    """The exact-operation table lives in the verifier: nothing from fns.strike."""
    source = Path(v.__file__).read_text(encoding="utf-8")
    assert "from fns.strike" not in source and "import fns.strike" not in source
    assert json.dumps(sorted(v.COUNTING)) == json.dumps(
        sorted([ADD_PASSWORD, ADD_OWNER, LIST_KEYS])
    )
