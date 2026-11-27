"""Strike runs against the fake tenant: undo always runs, verification, cleanup."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fns.exitcodes import ExitCode
from fns.journal.sqlite import SqliteJournal
from fns.scope.gate import DenyReason
from fns.strike.plan import PlanRejectedError, StrikePlan
from fns.strike.run import (
    StrikeJournal,
    StrikeRun,
    StrikeStartError,
    cleanup,
    pending_undos,
    run_plan,
)
from fns.strike.strikes import build_plan
from fns.strike.transport import StrikeRequest
from tests.factories import NOW, SP_AGENT
from tests.scope.writekit import ADD_PASSWORD, APP_ESC, LIST_KEYS, REGEN_KEY
from tests.strike.faketenant import (
    SCOPE_SHA,
    SECRET_PREFIX,
    Crash,
    FakeWrites,
    Fault,
    Lab,
    MemoryStrikeJournal,
    manifest,
)

RUN = "202611251200-abc123"
BEFORE: tuple[Any, ...] = ("S1", "S2", "S3")
AFTER: tuple[Any, ...] = ("D-1", "D-2", "D-3", "D-4", "D-5")


def plan_for(lab: Lab, strikes: tuple[Any, ...] = BEFORE) -> StrikePlan:
    return build_plan(strikes, lab.m, SCOPE_SHA, lab.reader(), NOW, run_id=RUN)


def go(
    lab: Lab,
    plan: StrikePlan,
    journal: StrikeJournal,
    writes: FakeWrites | None = None,
    **over: Any,
) -> StrikeRun:
    approve = over.pop("approve", plan.plan_hash())
    kwargs: dict[str, Any] = {
        "gate_factory": lab.gate_factory,
        "signed_in_principal": SP_AGENT,
        "scope_sha256": SCOPE_SHA,
        "transport": writes or FakeWrites(lab.tenant),
        "reader": lab.reader(),
        "journal": journal,
        "mode": "FIXTURE",
        "clock": lab.clock,
    }
    kwargs.update(over)
    return run_plan(plan, approve, **kwargs)


def clean(lab: Lab, plan: StrikePlan, journal: StrikeJournal) -> StrikeRun:
    return cleanup(
        plan,
        plan.plan_hash(),
        gate_factory=lab.gate_factory,
        signed_in_principal=SP_AGENT,
        transport=FakeWrites(lab.tenant),
        reader=lab.reader(),
        journal=journal,
    )


def restored(lab: Lab, before: dict[str, Any], *, s1: bool) -> bool:
    now = lab.tenant.snapshot()
    keys_ok = (
        all(now["keys"][k] > before["keys"][k] for k in ("key1", "key2"))
        if s1
        else now["keys"] == before["keys"]
    )
    return keys_ok and all(now[k] == before[k] for k in ("tags", "creds", "owners"))


def no_secrets(path: Path, lab: Lab, run: StrikeRun) -> None:
    raw = path.read_bytes()
    assert SECRET_PREFIX.encode() not in raw
    for s in lab.tenant.secrets_issued:
        assert s.encode() not in raw
        assert s not in str(run.to_dict())


@pytest.fixture
def jpath(tmp_path: Path) -> Path:
    return tmp_path / "journal.sqlite"


def test_happy_path(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    before = lab.tenant.snapshot()
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j)
        events = j.strike_events(RUN)
    assert run.exit_code == ExitCode.OK and run.verified and run.aborted is None
    assert [w.outcome for w in run.writes] == ["succeeded"] * 3
    assert [w.undo for w in run.writes] == [["200", "200"], ["200"], ["204"]]
    assert restored(lab, before, s1=True)
    sent = [(r.method, r.url.split("?")[0].rsplit("/", 1)[-1]) for r in lab.tenant.sent]
    assert sent == [
        ("POST", "listKeys"),
        ("PATCH", "kv-crown-jewels"),
        ("POST", "addPassword"),
        ("POST", "removePassword"),  # undo, reverse order
        ("PATCH", "kv-crown-jewels"),
        ("POST", "regenerateKey"),
        ("POST", "regenerateKey"),
    ]
    phases = [(k, ph) for k, ph, _ in events if k != "verify"]
    assert phases[:2] == [("S1/list-keys", "intent"), ("S1/list-keys", "result")]
    assert ("S3/add-password", "undo-result") in phases
    assert pending_undos(plan, events) == []
    no_secrets(jpath, lab, run)


def test_secrets_never_reach_the_journal_or_gate_records(jpath: Path) -> None:
    lab = Lab()
    with SqliteJournal(jpath) as j:
        run = go(lab, plan_for(lab), j)
    assert len(lab.tenant.secrets_issued) == 2 + 4 + 1  # listKeys, 2x regenerate, addPassword
    no_secrets(jpath, lab, run)
    for rec in lab.gate_journal.decisions:
        assert SECRET_PREFIX not in str(rec)


def test_every_write_went_through_the_write_gate(jpath: Path) -> None:
    lab = Lab()
    with SqliteJournal(jpath) as j:
        go(lab, plan_for(lab), j)
    strike = [r for r in lab.gate_journal.decisions if r.verb == "strike"]
    assert len(strike) == len(lab.tenant.sent) == 7
    assert all(r.decision == "allowed" and r.principal_id == SP_AGENT for r in strike)
    scout = [r for r in lab.gate_journal.decisions if r.verb == "scout"]
    assert scout and all(r.decision == "allowed" for r in scout)


@pytest.mark.parametrize("fault", ["500", "403", "raise-before", "raise-after"])
@pytest.mark.parametrize("at", [0, 1, 2])
def test_a_failed_write_still_undoes_everything(jpath: Path, fault: Fault, at: int) -> None:
    lab = Lab()
    plan = plan_for(lab)
    before = lab.tenant.snapshot()
    ok: list[Fault] = ["ok"]
    faults: list[Fault] = ok * at + [fault]
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j, FakeWrites(lab.tenant, faults))
    # a transport error looks the same before and after sending: assume it was sent
    s1_exposed = at > 0 or fault.startswith("raise")
    assert restored(lab, before, s1=s1_exposed)
    assert run.verified, run.checks
    expected = {"500": "failed", "403": "denied"}.get(fault, "unknown")
    assert run.writes[at].outcome == expected
    if fault.startswith("raise"):
        assert run.aborted is not None
        assert all(w.outcome == "not-run" for w in run.writes[at + 1 :])
    no_secrets(jpath, lab, run)


def test_lost_add_password_answer_is_found_by_name(jpath: Path) -> None:
    """The write happened, the answer (with keyId) is lost: the undo finds it."""
    lab = Lab()
    plan = plan_for(lab, ("S3",))
    before = lab.tenant.snapshot()
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j, FakeWrites(lab.tenant, ["raise-after"]))
    assert run.writes[0].outcome == "unknown" and run.writes[0].undo == ["204"]
    assert lab.tenant.snapshot() == before and run.exit_code == ExitCode.OK


def test_interrupt_still_undoes_then_propagates(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    before = lab.tenant.snapshot()
    writes = FakeWrites(lab.tenant)
    original = writes._exchange

    def interrupt(request: StrikeRequest) -> tuple[int, object, str | None]:
        if request.url.endswith("/addPassword"):
            raise KeyboardInterrupt
        return original(request)

    writes._exchange = interrupt  # type: ignore[method-assign]
    with SqliteJournal(jpath) as j, pytest.raises(KeyboardInterrupt):
        go(lab, plan, j, writes)
    assert restored(lab, before, s1=True)


def test_gate_denial_mid_run_undoes_and_exits_4(jpath: Path) -> None:
    lab = Lab(m=manifest(ops=(LIST_KEYS, REGEN_KEY, ADD_PASSWORD)))  # no vault write
    plan = plan_for(lab)
    before = lab.tenant.snapshot()
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j)
    assert [w.outcome for w in run.writes] == ["succeeded", "gate-denied", "not-run"]
    assert run.aborted is not None and "operation" in run.aborted
    assert run.exit_code == ExitCode.SCOPE_DENIED
    assert restored(lab, before, s1=True)
    assert lab.tenant.vault_tags == before["tags"]


def test_a_dropped_undo_is_caught_by_verification(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    writes = FakeWrites(lab.tenant)
    writes.drop = lambda r: r.url.endswith("/removePassword")
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j, writes)
    assert run.writes[2].undo == ["204"]  # it said it worked
    bad = [c for c in run.checks if not c.ok]
    assert [c.what for c in bad] == [f"credentials {APP_ESC}"]
    assert run.exit_code == ExitCode.EVIDENCE_INVALID


def test_a_skipped_key_regeneration_is_caught(jpath: Path) -> None:
    lab = Lab()
    writes = FakeWrites(lab.tenant)
    writes.drop = lambda r: r.url.split("?")[0].endswith("/regenerateKey")
    with SqliteJournal(jpath) as j:
        run = go(lab, plan_for(lab, ("S1",)), j, writes)
    assert run.exit_code == ExitCode.EVIDENCE_INVALID
    assert "not:" in run.checks[0].detail


# --- refusals before the first write -----------------------------------------------


def _refused(lab: Lab, plan: StrikePlan, jpath: Path, err: type[Exception], **over: Any) -> None:
    with SqliteJournal(jpath) as j, pytest.raises(err):
        go(lab, plan, j, **over)
    assert lab.tenant.sent == []


def test_wrong_hash(jpath: Path) -> None:
    lab = Lab()
    _refused(lab, plan_for(lab), jpath, PlanRejectedError, approve="0" * 64)


def test_wrong_identity(jpath: Path) -> None:
    lab = Lab()
    _refused(lab, plan_for(lab), jpath, StrikeStartError, signed_in_principal=APP_ESC)


def test_scope_file_changed(jpath: Path) -> None:
    lab = Lab()
    _refused(lab, plan_for(lab), jpath, StrikeStartError, scope_sha256="c" * 64)


def test_expired_plan(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    lab.clock.advance(3600)
    _refused(lab, plan, jpath, PlanRejectedError)


@pytest.mark.parametrize("change", ["tags", "creds", "keys"])
def test_lab_changed_since_planning(jpath: Path, change: str) -> None:
    lab = Lab()
    plan = plan_for(lab)
    if change == "tags":
        lab.tenant.vault_tags["owner"] = "someone"
    elif change == "creds":
        lab.tenant.creds[APP_ESC].append({"keyId": "00000000-0000-4000-8000-000000000999"})
    else:
        lab.tenant.key_times["key1"] = "2026-11-24T00:00:00Z"
    _refused(lab, plan, jpath, StrikeStartError)


def test_a_plan_runs_once(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    with SqliteJournal(jpath) as j:
        go(lab, plan, j)
        sent = len(lab.tenant.sent)
        with pytest.raises(StrikeStartError, match="already ran"):
            go(lab, plan, j)
    assert len(lab.tenant.sent) == sent


def test_a_lab_object_that_fails_the_live_check_is_never_written(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab, ("S3",))
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j, reader=_PreStateThenRenamed(lab))
    assert run.writes[0].outcome == "gate-denied"
    assert lab.tenant.sent == []
    assert run.aborted is not None and DenyReason.LAB_CHECK_FAILED.value in run.aborted
    assert run.exit_code == ExitCode.SCOPE_DENIED


class _PreStateThenRenamed:
    """Passes the pre-state re-read, then shows a renamed object to the lab check."""

    def __init__(self, lab: Lab) -> None:
        self.inner = lab.reader()
        self.calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def application(self, object_id: str) -> dict[str, Any]:
        self.calls += 1
        body = dict(self.inner.application(object_id))
        if self.calls == 2:  # 1: pre-state; 2: the live lab check
            body["displayName"] = "someone-elses-app"
        return body


# --- after harden (D6) ---------------------------------------------------------------


def test_after_harden_every_attempt_is_denied(jpath: Path) -> None:
    lab = Lab()
    lab.tenant.hardened = True
    plan = plan_for(lab, AFTER)
    before = lab.tenant.snapshot()
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j)
    assert [w.outcome for w in run.writes] == ["denied"] * 5
    assert all(w.status == 403 and w.undo == [] for w in run.writes)
    assert run.exit_code == ExitCode.OK and lab.tenant.snapshot() == before


@pytest.mark.parametrize("leak", ["D-1", "D-4"])
def test_an_attempt_that_succeeds_fails_the_contract_and_is_undone(jpath: Path, leak: str) -> None:
    lab = Lab()
    lab.tenant.hardened = True
    plan = plan_for(lab, AFTER)
    target = plan.write(f"{leak}/add-password" if leak == "D-1" else f"{leak}/add-owner")
    lab.tenant.leaky = {target.lab_objects[0]}
    before = lab.tenant.snapshot()
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j)
    leaked = [w for w in run.writes if w.outcome == "unexpected-success"]
    on_app = [w.strike for w in plan.writes if w.lab_objects == target.lab_objects]
    assert leak in on_app and [w.strike for w in leaked] == on_app
    assert all(w.undo == ["204"] for w in leaked)
    assert run.exit_code == ExitCode.CONTRACT_FAILED
    assert lab.tenant.snapshot() == before and run.verified


# --- cleanup after a crash -----------------------------------------------------------


def _crash_at(n: int) -> list[Fault]:
    ok: list[Fault] = ["ok"]
    return ok * n + ["crash-before"]


@pytest.mark.parametrize("n", range(7))
def test_cleanup_after_a_crash_at_every_send(jpath: Path, n: int) -> None:
    """The process dies at send n (a write or an undo); cleanup finishes the job."""
    lab = Lab()
    plan = plan_for(lab)
    before = lab.tenant.snapshot()
    with SqliteJournal(jpath) as j, pytest.raises(Crash):
        go(lab, plan, j, FakeWrites(lab.tenant, _crash_at(n)))
    with SqliteJournal(jpath) as j:
        run = clean(lab, plan, j)
        assert pending_undos(plan, j.strike_events(RUN)) == []
    assert run.verified, run.checks
    assert restored(lab, before, s1=True)
    no_secrets(jpath, lab, run)


def test_cleanup_with_nothing_to_do(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    with SqliteJournal(jpath) as j:
        go(lab, plan, j)
        sent = len(lab.tenant.sent)
        run = clean(lab, plan, j)
    assert run.writes == [] and run.verified and len(lab.tenant.sent) == sent


def test_cleanup_needs_the_run_and_the_agent(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    with SqliteJournal(jpath) as j:
        with pytest.raises(StrikeStartError, match="no run"):
            clean(lab, plan, j)
        with pytest.raises(PlanRejectedError):
            cleanup(
                plan,
                "0" * 64,
                gate_factory=lab.gate_factory,
                signed_in_principal=SP_AGENT,
                transport=FakeWrites(lab.tenant),
                reader=lab.reader(),
                journal=j,
            )


# --- fuzz: any fault schedule ends restored (after cleanup, if it crashed) -----------

faults = st.lists(
    st.sampled_from(
        ["ok", "ok", "ok", "500", "403", "raise-before", "raise-after", "crash-before"]
    ),
    max_size=9,
)


@settings(max_examples=150, deadline=None)
@given(schedule=faults, which=st.sampled_from([BEFORE, AFTER]), hardened=st.booleans())
def test_any_fault_schedule_ends_restored(
    schedule: list[Fault], which: tuple[Any, ...], hardened: bool
) -> None:
    lab = Lab()
    lab.tenant.hardened = hardened
    plan = plan_for(lab, which)
    before = lab.tenant.snapshot()
    j = MemoryStrikeJournal()
    try:
        run = go(lab, plan, j, FakeWrites(lab.tenant, schedule))
    except Crash:
        run = clean(lab, plan, j)
    if not run.verified:  # an undo itself failed: the runbook says run cleanup
        run = clean(lab, plan, j)
    assert run.verified, (schedule, run.checks)
    if pending_undos(plan, j.strike_events(RUN)):
        # the journal lacks an undo's answer (lost), though the state verified:
        # cleanup is conservative and sends it again, which must stay harmless
        assert clean(lab, plan, j).verified
    now = lab.tenant.snapshot()
    assert all(now[k] == before[k] for k in ("tags", "creds", "owners"))
    for secret in lab.tenant.secrets_issued:
        assert secret not in j.text() and secret not in str(run.to_dict())
