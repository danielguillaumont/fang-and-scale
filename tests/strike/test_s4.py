"""S4 against the fake tenant, with the conditions approved on 2026-11-27.

- the token is never persisted or logged: only its ``oid`` and ``roles`` claims are
  journaled;
- S4 runs only right after S3, in the same run;
- S3's password is removed as soon as S4 holds its token (or failed to get one);
- the marker role is Terraform's, on a lab app; the plan refuses without it;
- token claims that don't prove the capability stop S4 before any assignment;
- ``fns strike cleanup`` has no token, so it can't undo the assignment: exit 5
  until the runbook's emergency cleanup removes it.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

import pytest

from fns.adapters.azure.http import TransportError
from fns.exitcodes import ExitCode
from fns.scope.writes import CAPABILITY_ROLE, token_body
from fns.strike.plan import PlanError, StrikePlan
from fns.strike.run import (
    StrikeRun,
    StrikeStartError,
    cleanup,
    recorded_claims,
    run_plan,
    token_proof,
)
from fns.strike.secrets import ACCESS_TOKEN, HeldToken, SecretHolder
from fns.strike.strikes import ASSIGN_KEY, S3_KEY, TOKEN_KEY, build_plan
from fns.strike.transport import (
    TOKEN_FIELDS,
    HttpTokenTransport,
    TokenWire,
    check_token_wire,
)
from tests.factories import NOW, SP_AGENT, TENANT, pid
from tests.livekit import Canned, FakeOpener
from tests.scope.writekit import (
    APP_ESC,
    ESC_APPID,
    MARKER,
    PRE_ROLES,
    SP_ESC,
    strike_dict,
)
from tests.strike.faketenant import (
    SCOPE_SHA,
    SECRET_PREFIX,
    FakeEscalatedWrites,
    FakeWrites,
    Lab,
    MemoryStrikeJournal,
    manifest,
)

RUN = "202611271200-s4test"
ALL: tuple[Any, ...] = ("S1", "S2", "S3", "S4")
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"


def plan_for(lab: Lab, strikes: tuple[Any, ...] = ALL) -> StrikePlan:
    return build_plan(strikes, lab.m, SCOPE_SHA, lab.reader(), NOW, run_id=RUN)


def go(lab: Lab, plan: StrikePlan, journal: MemoryStrikeJournal, **over: Any) -> StrikeRun:
    kwargs: dict[str, Any] = {
        "gate_factory": lab.gate_factory,
        "signed_in_principal": SP_AGENT,
        "scope_sha256": SCOPE_SHA,
        "transport": FakeWrites(lab.tenant),
        "reader": lab.reader(),
        "journal": journal,
        "mode": "FIXTURE",
        "clock": lab.clock,
        "escalation": lab.escalation(),
    }
    kwargs.update(over)
    return run_plan(plan, plan.plan_hash(), **kwargs)


def state(lab: Lab) -> dict[str, Any]:
    """The tenant without the storage keys (S1's undo regenerates them, by design)."""
    return {k: v for k, v in lab.tenant.snapshot().items() if k != "keys"}


def outcome(run: StrikeRun, key: str) -> str:
    return next(w.outcome for w in run.writes if w.key == key)


def events(journal: MemoryStrikeJournal, key: str, phase: str) -> list[dict[str, Any]]:
    return [d for k, ph, d in journal.strike_events(RUN) if k == key and ph == phase]


def everything_written(lab: Lab, journal: MemoryStrikeJournal, run: StrikeRun) -> str:
    return journal.text() + json.dumps(run.to_dict()) + repr(lab.gate_journal.decisions)


# --- the plan ----------------------------------------------------------------------------


def test_the_plan_puts_the_token_right_after_s3_and_the_assignment_as_the_escalated_identity() -> (
    None
):
    plan = plan_for(Lab())
    keys = [w.key for w in plan.writes]
    assert keys[keys.index(S3_KEY) + 1 : keys.index(S3_KEY) + 3] == [TOKEN_KEY, ASSIGN_KEY]
    token, assign = plan.writes[-2:]
    assert token.request.body == token_body(ESC_APPID) and token.request.url == TOKEN_URL
    assert token.undo == () and token.request.acts_as is None
    assert assign.request.acts_as == "escalated" and assign.undo[0].acts_as == "escalated"
    assert assign.request.body == {
        "principalId": SP_AGENT,
        "resourceId": SP_ESC,
        "appRoleId": MARKER["id"],
    }
    assert f"assigned:{SP_ESC}" in plan.pre_state
    assert "client_secret" not in plan.canonical_json()


def test_a_plan_without_s4_is_unchanged_by_it() -> None:
    plan = plan_for(Lab(), ("S1", "S2", "S3"))
    assert "escalation_sp" not in plan.targets and "acts_as" not in plan.canonical_json()


@pytest.mark.parametrize("strikes", [("S4",), ("S1", "S4"), ("S2", "S4")])
def test_s4_runs_only_with_s3_in_the_same_run(strikes: tuple[Any, ...]) -> None:
    with pytest.raises(PlanError, match="S4 runs only right after S3"):
        plan_for(Lab(), strikes)


def test_s4_needs_the_escalation_block() -> None:
    lab = Lab(m=manifest(strike=strike_dict(escalation=None)))
    with pytest.raises(PlanError, match=r"strike\.escalation"):
        plan_for(lab)


@pytest.mark.parametrize(
    ("roles", "why"),
    [
        (PRE_ROLES, "not defined"),
        ([*PRE_ROLES, {**MARKER, "isEnabled": False}], ""),
        ([*PRE_ROLES, {**MARKER, "description": "Reads payroll"}], ""),
        ([*PRE_ROLES, {**MARKER, "allowedMemberTypes": ["User"]}], ""),
    ],
    ids=["no marker", "disabled", "grants something", "for users"],
)
def test_s4_needs_terraforms_marker_on_the_lab_app(roles: list[dict[str, Any]], why: str) -> None:
    lab = Lab()
    lab.tenant.roles[APP_ESC] = roles
    with pytest.raises(PlanError, match=f"S4: .*{why}"):
        plan_for(lab)


def test_s4_refuses_a_marker_that_is_already_assigned() -> None:
    lab = Lab()
    lab.tenant.assigned.append(
        {"id": "fakeLeftOverAssign01", "principalId": SP_AGENT, "appRoleId": MARKER["id"]}
    )
    with pytest.raises(PlanError, match="already assigned"):
        plan_for(lab)


def test_a_plan_with_s4_needs_the_escalation_dependency() -> None:
    lab = Lab()
    with pytest.raises(StrikeStartError, match="S4 needs"):
        go(lab, plan_for(lab), MemoryStrikeJournal(), escalation=None)
    assert lab.tenant.sent == []


# --- the run -----------------------------------------------------------------------------


def test_s4_assigns_the_marker_as_the_escalated_identity_and_undoes_it() -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    before = state(lab)
    run = go(lab, plan_for(lab), journal)
    assert run.verified and run.exit_code is ExitCode.OK, run.checks
    assert outcome(run, TOKEN_KEY) == "succeeded" and outcome(run, ASSIGN_KEY) == "succeeded"
    assert state(lab) == before
    posts = [r for r in lab.tenant.sent if r.url.endswith("/appRoleAssignedTo")]
    deletes = [r for r in lab.tenant.sent if "/appRoleAssignedTo/" in r.url]
    assert len(posts) == 1 and len(deletes) == 1
    assert any(c.what == f"app role assignments {SP_ESC}" and c.ok for c in run.checks)


def test_the_token_is_never_persisted_or_logged() -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    run = go(lab, plan_for(lab), journal)
    (token,) = lab.tenant.tokens
    written = everything_written(lab, journal, run)
    assert token not in written and token.split(".")[1] not in written
    assert SECRET_PREFIX not in written and "access_token" not in written
    for secret in lab.tenant.secrets_issued:
        assert secret not in written


def test_only_the_oid_and_roles_claims_are_recorded() -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    go(lab, plan_for(lab), journal)
    (result,) = events(journal, TOKEN_KEY, "result")
    assert result["claims"] == {
        "oid": SP_ESC,
        "roles": sorted(["Application.Read.All", CAPABILITY_ROLE]),
    }
    assert result["safety_stop"] == "passed" and result["learned"] == {}
    assert TENANT not in json.dumps(result["claims"]) and ESC_APPID not in json.dumps(result)


def test_the_token_request_carries_the_secret_only_on_the_wire() -> None:
    lab = Lab()
    go(lab, plan_for(lab), MemoryStrikeJournal())
    assert lab.tokens is not None
    (wire,) = lab.tokens.wires
    assert set(wire.form) == TOKEN_FIELDS and wire.url == TOKEN_URL
    (seen,) = lab.tenant.token_secrets_seen
    assert seen.startswith(SECRET_PREFIX)  # S3's password, from the holder


def test_s3s_password_is_removed_as_soon_as_s4_holds_its_token() -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    run = go(lab, plan_for(lab), journal)
    order = [r.url.rsplit("/", 1)[-1] for r in lab.tenant.sent]
    assert order.index("removePassword") < order.index("appRoleAssignedTo")
    assert next(w for w in run.writes if w.key == S3_KEY).undo == ["204"]
    rows = [(k, ph) for k, ph, _ in journal.strike_events(RUN)]
    assert rows.index((S3_KEY, "undo-result")) < rows.index((ASSIGN_KEY, "intent"))


def bad_claims() -> list[tuple[str, dict[str, Any]]]:
    return [
        ("another oid", {"oid": pid(990)}),
        ("the agent's oid", {"oid": SP_AGENT}),
        ("no roles", {"roles": None}),
        ("roles without the capability", {"roles": ["Application.Read.All"]}),
        ("a roles string", {"roles": CAPABILITY_ROLE}),
        ("another tenant", {"tid": pid(9)}),
        ("another app", {"appid": pid(301)}),
    ]


@pytest.mark.parametrize(("name", "claims"), bad_claims(), ids=[n for n, _ in bad_claims()])
def test_claims_that_do_not_prove_the_capability_stop_s4(name: str, claims: dict[str, Any]) -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    lab.tenant.token_claims = claims
    before = state(lab)
    run = go(lab, plan_for(lab), journal)
    assert outcome(run, TOKEN_KEY) == "failed", name
    assert outcome(run, ASSIGN_KEY) == "not-run"
    assert not [r for r in lab.tenant.sent if "appRoleAssignedTo" in r.url]
    assert lab.esc_writes == []  # no escalated transport was ever made
    assert state(lab) == before and run.verified  # S3's password is gone too
    (result,) = events(journal, TOKEN_KEY, "result")
    assert result["safety_stop"] != "passed"
    assert SECRET_PREFIX not in everything_written(lab, journal, run)


def test_a_refused_token_request_stops_s4_and_still_removes_s3s_password() -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    lab.tenant.token_status = 401
    before = state(lab)
    run = go(lab, plan_for(lab), journal)
    assert outcome(run, TOKEN_KEY) == "denied" and outcome(run, ASSIGN_KEY) == "not-run"
    assert state(lab) == before and run.verified


def test_a_lost_token_answer_aborts_and_undoes_everything() -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    assert lab.tokens is not None
    lab.tokens.fault = "raise-after"
    before = state(lab)
    run = go(lab, plan_for(lab), journal)
    assert run.aborted is not None and outcome(run, TOKEN_KEY) == "unknown"
    assert outcome(run, ASSIGN_KEY) == "not-run"
    assert state(lab) == before and run.verified


def test_a_lost_assignment_answer_is_resolved_by_the_scout_and_undone() -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    lab.esc_faults = ["raise-after"]
    before = state(lab)
    run = go(lab, plan_for(lab), journal)
    assert outcome(run, ASSIGN_KEY) == "unknown"
    assert state(lab) == before and run.verified, run.checks


class _AgentsToken:
    def token(self, api: str) -> str:
        return "the-agents-own-token"


def test_the_assignment_needs_the_held_token_not_the_agents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The fake tenant answers 403 to an assignment without S4's token, as Entra would.
    lab = Lab()
    monkeypatch.setattr(
        lab, "escalated_transport", lambda tokens: FakeEscalatedWrites(lab.tenant, _AgentsToken())
    )
    run = go(lab, plan_for(lab), MemoryStrikeJournal())
    assert outcome(run, ASSIGN_KEY) == "denied" and run.verified


def test_a_failed_removal_leaves_exit_5_and_cleanup_cannot_fix_it() -> None:
    lab, journal = Lab(), MemoryStrikeJournal()
    lab.esc_faults = ["ok", "500"]  # the assignment, then its removal fails
    plan = plan_for(lab)
    run = go(lab, plan, journal)
    assert run.exit_code is ExitCode.EVIDENCE_INVALID
    assert any(a["appRoleId"] == MARKER["id"] for a in lab.tenant.assigned)

    def clean() -> StrikeRun:
        return cleanup(
            plan,
            plan.plan_hash(),
            gate_factory=lab.gate_factory,
            signed_in_principal=SP_AGENT,
            transport=FakeWrites(lab.tenant),
            reader=lab.reader(),
            journal=journal,
        )

    again = clean()
    (w,) = again.writes
    assert w.key == ASSIGN_KEY and w.undo == ["needs-emergency-cleanup"]
    assert again.exit_code is ExitCode.EVIDENCE_INVALID
    # the runbook's emergency cleanup (an admin, outside the tool) removes it:
    lab.tenant.assigned = [a for a in lab.tenant.assigned if a["appRoleId"] != MARKER["id"]]
    assert clean().exit_code is ExitCode.OK


# --- the pieces --------------------------------------------------------------------------


def test_recorded_claims_keep_oid_and_roles_only() -> None:
    claims = {"oid": SP_ESC.upper(), "roles": ["b", "a"], "tid": TENANT, "appid": ESC_APPID}
    assert recorded_claims(claims) == {"oid": SP_ESC, "roles": ["a", "b"]}
    assert recorded_claims({}) == {"oid": "", "roles": []}


def test_token_proof_reads_every_claim() -> None:
    plan = plan_for(Lab())
    good = {"tid": TENANT, "oid": SP_ESC, "appid": ESC_APPID, "roles": [CAPABILITY_ROLE]}
    assert token_proof(good, plan) is None
    assert token_proof({**good, "appid": None, "azp": ESC_APPID}, plan) is None
    for name, change in bad_claims():
        assert token_proof({**good, **change}, plan) is not None, name


def test_held_token_is_graph_only_and_ends_with_the_holder() -> None:
    holder = SecretHolder()
    holder.put(TOKEN_KEY, {ACCESS_TOKEN: "FAKE-SECRET-tok"})
    held = HeldToken(holder, TOKEN_KEY)
    assert held.token("graph") == "FAKE-SECRET-tok"
    assert "FAKE-SECRET" not in repr(held)
    with pytest.raises(TransportError, match="no arm token"):
        held.token("arm")
    holder.drop(TOKEN_KEY)
    with pytest.raises(TransportError, match="gone"):
        held.token("graph")


FORM = token_body(ESC_APPID)


@pytest.mark.parametrize(
    "wire",
    [
        TokenWire(TOKEN_URL.replace("https", "http"), FORM),
        TokenWire(TOKEN_URL.replace("login.microsoftonline.com", "login.example"), FORM),
        TokenWire(TOKEN_URL.replace(".com/", ".com:8443/"), FORM),
        TokenWire(TOKEN_URL.replace("https://", "https://u:p@"), FORM),
        TokenWire(f"{TOKEN_URL}?x=1", FORM),
        TokenWire(f"{TOKEN_URL}#x", FORM),
        TokenWire(TOKEN_URL.replace("/v2.0", ""), FORM),
        TokenWire(TOKEN_URL.replace(TENANT, "common"), FORM),
        TokenWire(TOKEN_URL, {**FORM, "client_secret": "x"}),
        TokenWire(TOKEN_URL, {k: v for k, v in FORM.items() if k != "scope"}),
    ],
)
def test_the_token_transport_refuses_anything_else(wire: TokenWire) -> None:
    opener = FakeOpener()
    with pytest.raises(TransportError):
        HttpTokenTransport(opener=opener).send_token(wire, "s", SecretHolder(), TOKEN_KEY)
    with pytest.raises(TransportError):
        check_token_wire(wire)
    assert opener.requests == []


def test_the_live_token_transport_sends_a_form_and_strips_the_token() -> None:
    answer = {"token_type": "Bearer", "expires_in": 3599, "access_token": "FAKE-SECRET-jwt"}
    opener = FakeOpener({TOKEN_URL: Canned(200, answer, {"x-ms-request-id": "rid-9"})})
    holder = SecretHolder()
    resp = HttpTokenTransport(opener=opener).send_token(
        TokenWire(TOKEN_URL, FORM), "FAKE-SECRET-pw", holder, TOKEN_KEY
    )
    assert resp.ok and resp.request_id == "rid-9" and resp.secrets_removed == 1
    assert "FAKE-SECRET" not in json.dumps(resp.body)
    assert holder.get(TOKEN_KEY, ACCESS_TOKEN) == "FAKE-SECRET-jwt"
    (sent,) = opener.requests
    assert isinstance(sent, urllib.request.Request) and sent.get_method() == "POST"
    assert sent.get_header("Content-type") == "application/x-www-form-urlencoded"
    assert sent.get_header("Authorization") is None
    assert isinstance(sent.data, bytes) and b"client_secret=FAKE-SECRET-pw" in sent.data


def test_the_token_transport_needs_a_secret() -> None:
    opener = FakeOpener()
    with pytest.raises(TransportError, match="no client secret"):
        HttpTokenTransport(opener=opener).send_token(
            TokenWire(TOKEN_URL, FORM), "", SecretHolder(), TOKEN_KEY
        )
    assert opener.requests == []
