"""Strike plans: what is planned, the hash, approval, and the one-request binding."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest

from fns.scope.gate import WriteRequest
from fns.strike.plan import (
    ApprovedPlan,
    PlanError,
    PlanRejectedError,
    StrikePlan,
    UnresolvedError,
    needs,
    render_request,
)
from fns.strike.strikes import build_plan, lab_targets
from tests.factories import NOW, SP_AGENT, TENANT
from tests.scope.writekit import APP_ESC, APP_SCOUT, APP_VER, PAYROLL, VAULT
from tests.strike.faketenant import SCOPE_SHA, Lab

RUN = "202611251200-abc123"


def plan_for(strikes: tuple[Any, ...] = ("S1", "S2", "S3"), lab: Lab | None = None) -> StrikePlan:
    lab = lab or Lab()
    return build_plan(strikes, lab.m, SCOPE_SHA, lab.reader(), NOW, run_id=RUN)


def test_targets_come_from_the_scope() -> None:
    t = lab_targets(Lab().m)
    assert (t.agent, t.payroll, t.vault) == (SP_AGENT, PAYROLL, VAULT)
    assert (t.escalation_app, t.verifier_app, t.scout_app) == (APP_ESC, APP_VER, APP_SCOUT)


def test_before_harden_plan() -> None:
    plan = plan_for()
    assert [w.key for w in plan.writes] == ["S1/list-keys", "S2/vault-tag", "S3/add-password"]
    s1, s2, s3 = plan.writes
    assert [u.body for u in s1.undo] == [{"keyName": "key1"}, {"keyName": "key2"}]  # SD1
    assert s2.request.body == {
        "tags": {"project": "fang-and-scale", "purpose": "lab", "fns-strike": RUN}
    }
    assert s2.undo[0].body == {"tags": {"project": "fang-and-scale", "purpose": "lab"}}
    cred = s3.request.body["passwordCredential"]
    assert cred == {"displayName": f"fns-strike-{RUN}", "endDateTime": "2026-11-25T13:00:00Z"}
    assert s3.undo[0].body == {"keyId": "{{learned:S3/add-password:keyId}}"}
    assert s3.lab_objects == (APP_ESC,)
    assert all(w.expect == "allowed" for w in plan.writes)
    assert plan.tenant_id == TENANT and plan.agent_object_id == SP_AGENT
    assert plan.expires_at == NOW + timedelta(hours=1)


def test_after_harden_plan_expects_denials() -> None:
    plan = plan_for(("D-1", "D-2", "D-3", "D-4", "D-5"))
    assert [w.key for w in plan.writes] == [
        "D-1/add-password",
        "D-2/add-password",
        "D-3/add-password",
        "D-4/add-owner",
        "D-5/add-owner",
    ]
    assert all(w.expect == "denied" and w.undo and w.observes for w in plan.writes)
    assert plan.writes[1].observes == (
        "application:id-verifier credentials/update",
        "directory:tenant applications/credentials/update",
    )
    assert not any(w.observes for w in plan_for().writes)
    assert [w.lab_objects[0] for w in plan.writes] == [
        APP_ESC,
        APP_VER,
        APP_SCOUT,
        APP_VER,
        APP_SCOUT,
    ]
    assert plan.writes[3].request.body == {
        "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{SP_AGENT}"
    }
    assert set(plan.pre_state) == {
        f"app:{APP_ESC}",
        f"app:{APP_VER}",
        f"app:{APP_SCOUT}",
        f"owners:{APP_VER}",
        f"owners:{APP_SCOUT}",
    }


@pytest.mark.parametrize(
    ("strikes", "message"),
    [
        (("S4",), "not built yet"),
        (("S1", "D-1"), "separately"),
        (("S1", "S1"), "twice"),
        (("X9",), "not built yet"),
    ],
)
def test_refused_plans(strikes: tuple[Any, ...], message: str) -> None:
    with pytest.raises(PlanError, match=message):
        plan_for(strikes)


def test_order_is_fixed_whatever_the_input_order() -> None:
    assert plan_for(("S3", "S1")).strikes == ("S1", "S3")


def test_a_leftover_strike_tag_stops_planning() -> None:
    lab = Lab()
    lab.tenant.vault_tags["fns-strike"] = "older-run"
    with pytest.raises(PlanError, match="clean up first"):
        plan_for(("S2",), lab)


@pytest.mark.parametrize("what", ["storage", "vault"])
def test_an_untagged_arm_target_is_not_a_lab_resource(what: str) -> None:
    lab = Lab()
    if what == "storage":
        lab.tenant.storage_tags = {"project": "fang-and-scale"}
    else:
        lab.tenant.vault_tags = {"purpose": "lab", "project": "something-else"}
    with pytest.raises(PlanError, match="not a lab resource"):
        plan_for(("S1",) if what == "storage" else ("S2",), lab)


def test_no_strike_block_no_plan() -> None:
    lab = Lab()
    lab.m = lab.m.model_copy(update={"strike": None})
    with pytest.raises(PlanError, match="strike: block"):
        lab_targets(lab.m)


# --- hash and approval ------------------------------------------------------------


def test_hash_is_stable_and_survives_a_round_trip() -> None:
    a, b = plan_for(), plan_for()
    assert a.plan_hash() == b.plan_hash()
    again = StrikePlan.model_validate_json(a.canonical_json())
    assert again.plan_hash() == a.plan_hash()


def _mutations(plan: StrikePlan) -> list[StrikePlan]:
    data = json.loads(plan.canonical_json())
    out = []
    edits: list[Callable[[dict[str, Any]], object]] = [
        lambda d: d.update(run_id="202611251200-zzzzzz"),
        lambda d: d.update(scope_sha256="b" * 64),
        lambda d: d.update(agent_object_id=APP_VER),
        lambda d: d.update(expires_at="2026-11-25T14:00:00Z"),
        lambda d: d["writes"][0]["request"].update(url=d["writes"][0]["request"]["url"] + "&x=1"),
        lambda d: d["writes"][1]["request"]["body"]["tags"].update(extra="1"),
        lambda d: d["writes"][1]["undo"][0]["body"]["tags"].update(purpose="x"),
        lambda d: d["writes"][2].update(undo=[]),
        lambda d: d["writes"][2].update(expect="denied"),
        lambda d: d["pre_state"][f"app:{APP_ESC}"]["passwordCredentials"].clear(),
        lambda d: d.update(writes=d["writes"][:2]),
    ]
    for edit in edits:
        d = json.loads(json.dumps(data))
        edit(d)
        out.append(StrikePlan.model_validate(d))
    return out


def test_every_change_changes_the_hash() -> None:
    plan = plan_for()
    hashes = {m.plan_hash() for m in _mutations(plan)}
    assert plan.plan_hash() not in hashes
    assert len(hashes) == len(_mutations(plan))


def test_a_tampered_plan_is_refused() -> None:
    plan = plan_for()
    for m in _mutations(plan):
        with pytest.raises(PlanRejectedError, match="does not match"):
            ApprovedPlan(m, plan.plan_hash())


@pytest.mark.parametrize("prefix", ["", "sha256:"])
def test_approve_accepts_the_printed_form(prefix: str) -> None:
    plan = plan_for()
    ApprovedPlan(plan, prefix + plan.plan_hash())


@pytest.mark.parametrize("bad", ["", "sha256:", "0" * 64, "SHA256:x"])
def test_approve_refuses_anything_else(bad: str) -> None:
    with pytest.raises(PlanRejectedError):
        ApprovedPlan(plan_for(), bad)


def test_expiry() -> None:
    plan = plan_for()
    approved = ApprovedPlan(plan, plan.plan_hash())
    approved.check_fresh(NOW + timedelta(minutes=59))
    with pytest.raises(PlanRejectedError, match="expired"):
        approved.check_fresh(NOW + timedelta(hours=1))


# --- binding ------------------------------------------------------------------------


def _wire(r: Any) -> WriteRequest:
    return WriteRequest(
        verb="strike",
        operation=r.operation,
        method=r.method,
        url=r.url,
        body=r.body,
        tenant_id=TENANT,
    )


def test_binding_admits_only_the_armed_request_once() -> None:
    plan = plan_for()
    binding = ApprovedPlan(plan, plan.plan_hash())
    first = render_request(plan.writes[0].request, {})
    second = render_request(plan.writes[1].request, {})
    assert not binding.admits(_wire(first), first.body_digest)  # nothing armed
    binding.arm(first)
    assert not binding.admits(_wire(second), second.body_digest)  # out of turn
    assert binding.admits(_wire(first), first.body_digest)
    assert not binding.admits(_wire(first), first.body_digest)  # not twice
    assert binding.sent == (first,)


def test_binding_compares_the_body_digest() -> None:
    plan = plan_for()
    binding = ApprovedPlan(plan, plan.plan_hash())
    r = render_request(plan.writes[1].request, {})
    binding.arm(r)
    assert not binding.admits(_wire(r), "0" * 64)


def test_cannot_arm_an_unplanned_form() -> None:
    plan = plan_for(("S2",))
    binding = ApprovedPlan(plan, plan.plan_hash())
    other = render_request(plan_for(("S3",)).writes[0].request, {})
    with pytest.raises(PlanRejectedError, match="not in the plan"):
        binding.arm(other)


def test_learned_values() -> None:
    undo = plan_for().writes[2].undo[0]
    assert needs(undo.model_dump()) == {"S3/add-password"}
    with pytest.raises(UnresolvedError):
        render_request(undo, {})
    with pytest.raises(UnresolvedError):
        render_request(undo, {"S3/add-password": {"keyId": ""}})
    r = render_request(undo, {"S3/add-password": {"keyId": "abc"}})
    assert r.body == {"keyId": "abc"}
