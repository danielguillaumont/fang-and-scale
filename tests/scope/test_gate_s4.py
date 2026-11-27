"""S4's two gate rules (approved 2026-11-27): the token request, and the escalated identity.

Every rule has a negative test here: a scope without ``strike.escalation``, a forged
scope, the hard denylist, and every way the token request or an escalated write can
differ from the one S4 needs. Placeholder GUIDs only.
"""

from __future__ import annotations

import copy
import uuid
from dataclasses import replace
from typing import Any

import pytest
from pydantic import ValidationError

from fns.models.operations import WRITE_FORM_OPERATIONS
from fns.models.scope import ScopeManifest, StrikeEscalation, StrikeScope
from fns.scope.gate import Allowed, Denied, DenyReason, FrozenClock, Gate, WriteRequest
from fns.scope.writes import TOKEN_OPERATION, token_body, token_url
from tests.factories import SP_AGENT, TENANT, pid
from tests.scope.writekit import (
    APP_ESC,
    APPS,
    ASSIGN,
    ESC_APPID,
    ESCALATED_FORMS,
    GRAPH,
    GRAPH_APP_ID,
    MARKER,
    PRE_ROLES,
    SP_ESC,
    STRIKE_UNTIL,
    UNASSIGN,
    VER_APPID,
    Exactly,
    app_json,
    escalated_gate,
    req,
    sp_json,
    strike_dict,
    strike_manifest,
    valid,
    write_gate,
)

TOKEN_URL = token_url(uuid.UUID(TENANT))


def token_request(**over: Any) -> WriteRequest:
    return replace(req(TOKEN_OPERATION, "POST", TOKEN_URL, token_body(ESC_APPID)), **over)


def _denied(gate: Gate, r: WriteRequest) -> Denied:
    d = gate.check_write(r)
    assert isinstance(d, Denied), d
    return d


def _no_escalation() -> ScopeManifest:
    return strike_manifest(strike={k: v for k, v in strike_dict().items() if k != "escalation"})


# --- the token request ----------------------------------------------------------------


def test_the_token_request_is_allowed_when_every_rule_holds() -> None:
    gate, journal, _ = write_gate()
    d = gate.check_write(token_request())
    assert isinstance(d, Allowed) and d.target == f"directory/{SP_ESC}", d
    gate.call_write(token_request(), lambda: None)
    (row,) = journal.decisions
    assert row.decision == "allowed" and row.url == TOKEN_URL
    assert "client_secret" not in row.detail and row.detail.startswith("POST body sha256:")


def test_the_token_body_never_holds_the_secret() -> None:
    assert set(token_body(ESC_APPID)) == {"client_id", "grant_type", "scope"}


T = TOKEN_URL
TOKEN_ROWS: list[tuple[str, DenyReason, dict[str, Any]]] = [
    ("another tenant", DenyReason.BAD_URL, {"url": token_url(uuid.UUID(pid(9)))}),
    ("v1 endpoint", DenyReason.BAD_URL, {"url": T.replace("/v2.0", "")}),
    ("http", DenyReason.BAD_URL, {"url": T.replace("https:", "http:")}),
    ("other host", DenyReason.BAD_URL, {"url": T.replace("login.microsoftonline.com", "x.test")}),
    ("a query", DenyReason.BAD_URL, {"url": f"{T}?x=1"}),
    ("trailing slash", DenyReason.BAD_URL, {"url": f"{T}/"}),
    ("upper case host", DenyReason.BAD_URL, {"url": T.replace("login", "LOGIN")}),
    ("GET", DenyReason.BAD_URL, {"method": "GET"}),
    (
        "the secret in the body",
        DenyReason.BAD_BODY,
        {"body": {**token_body(ESC_APPID), "client_secret": "x"}},
    ),
    ("another app", DenyReason.BAD_BODY, {"body": token_body(VER_APPID)}),
    ("Graph's own app", DenyReason.HARD_DENY, {"body": token_body(GRAPH_APP_ID)}),
    ("client_id in braces", DenyReason.BAD_BODY, {"body": token_body(f"{{{ESC_APPID}}}")}),
    (
        "ARM scope",
        DenyReason.BAD_BODY,
        {"body": {**token_body(ESC_APPID), "scope": "https://management.azure.com/.default"}},
    ),
    (
        "a narrower Graph scope",
        DenyReason.BAD_BODY,
        {"body": {**token_body(ESC_APPID), "scope": "AppRoleAssignment.ReadWrite.All"}},
    ),
    (
        "password grant",
        DenyReason.BAD_BODY,
        {"body": {**token_body(ESC_APPID), "grant_type": "password"}},
    ),
    ("an extra field", DenyReason.BAD_BODY, {"body": {**token_body(ESC_APPID), "x": "1"}}),
    ("no body", DenyReason.BAD_BODY, {"body": None}),
    ("another verb", DenyReason.VERB_NOT_ALLOWED, {"verb": "prove"}),
    ("another tenant id", DenyReason.TENANT_MISMATCH, {"tenant_id": pid(9)}),
    (
        "a denied path",
        DenyReason.HARD_DENY,
        {"url": f"https://login.microsoftonline.com/{TENANT}/roleManagement/token"},
    ),
]


@pytest.mark.parametrize(("name", "reason", "change"), TOKEN_ROWS, ids=[r[0] for r in TOKEN_ROWS])
def test_the_token_request_is_refused(
    name: str, reason: DenyReason, change: dict[str, Any]
) -> None:
    gate, _, _ = write_gate()
    d = _denied(gate, token_request(**change))
    assert d.reason is reason, f"{name}: {d.reason} ({d.detail})"


def test_no_escalation_block_means_no_token_request() -> None:
    gate, _, _ = write_gate(_no_escalation())
    assert _denied(gate, token_request()).reason is DenyReason.NO_STRIKE_SCOPE


def test_the_token_request_needs_the_live_check_of_the_app_and_its_sp() -> None:
    gate, _, _ = write_gate(confirm=False)
    assert _denied(gate, token_request()).reason is DenyReason.LAB_CHECK_FAILED
    assert gate.record_lab_check(APP_ESC, app_json(APP_ESC)) is None
    assert _denied(gate, token_request()).reason is DenyReason.LAB_CHECK_FAILED
    assert gate.record_lab_check(SP_ESC, sp_json()) is None
    assert isinstance(gate.check_write(token_request()), Allowed)


@pytest.mark.parametrize("principal", [SP_ESC, pid(150), None])
def test_only_a_test_identity_sends_the_token_request(principal: str | None) -> None:
    gate, _, _ = write_gate(principal=principal)
    assert _denied(gate, token_request()).reason is DenyReason.PRINCIPAL_NOT_ALLOWED


def test_the_token_request_needs_the_approved_plan_and_the_budget() -> None:
    gate, _, _ = write_gate(plan=None)
    assert _denied(gate, token_request()).reason is DenyReason.NO_APPROVED_PLAN
    gate, _, _ = write_gate(plan=Exactly(set()))
    assert _denied(gate, token_request()).reason is DenyReason.NOT_IN_APPROVED_PLAN
    gate, _, _ = write_gate(strike_manifest(budget={"max_api_calls": 1, "max_minutes": 60}))
    gate.call_write(token_request(), lambda: None)
    assert _denied(gate, token_request()).reason is DenyReason.BUDGET_CALLS


def test_the_token_request_stops_when_the_strike_scope_expires() -> None:
    gate, _, _ = write_gate(clock=FrozenClock(STRIKE_UNTIL))
    assert _denied(gate, token_request()).reason is DenyReason.EXPIRED


# --- the escalated identity -----------------------------------------------------------


@pytest.mark.parametrize("op", ESCALATED_FORMS)
def test_the_escalated_identity_may_send_the_marker_assignment_and_its_removal(op: str) -> None:
    gate, _, _ = escalated_gate()
    assert isinstance(gate.check_write(valid(op)), Allowed)


@pytest.mark.parametrize("op", [o for o in WRITE_FORM_OPERATIONS if o not in ESCALATED_FORMS])
def test_the_escalated_identity_may_send_nothing_else(op: str) -> None:
    gate, _, _ = escalated_gate()
    d = _denied(gate, valid(op))
    assert d.reason is DenyReason.PRINCIPAL_NOT_ALLOWED and "escalated" in d.detail


def test_the_escalated_identity_never_asks_for_a_token() -> None:
    gate, _, _ = escalated_gate()
    assert _denied(gate, token_request()).reason is DenyReason.PRINCIPAL_NOT_ALLOWED


@pytest.mark.parametrize("op", ESCALATED_FORMS)
def test_a_test_identity_never_assigns_the_marker(op: str) -> None:
    gate, _, _ = write_gate()
    d = _denied(gate, valid(op))
    assert d.reason is DenyReason.PRINCIPAL_NOT_ALLOWED and "escalated" in d.detail


@pytest.mark.parametrize("op", ESCALATED_FORMS)
def test_without_the_escalation_block_the_target_is_just_another_identity(op: str) -> None:
    gate, _, _ = escalated_gate(_no_escalation())
    assert _denied(gate, valid(op)).reason is DenyReason.PRINCIPAL_NOT_ALLOWED


def test_the_escalated_identity_writes_only_to_its_own_service_principal() -> None:
    m = strike_manifest(
        strike=strike_dict(
            targets=[
                *strike_dict()["targets"],
                {
                    "kind": "graph-service-principal",
                    "id": pid(204),
                    "display_name": "sp-fns-scout",
                    "application": pid(203),
                },
            ]
        )
    )
    gate, _, _ = escalated_gate(m)
    other = replace(
        valid(ASSIGN),
        url=f"{GRAPH}/servicePrincipals/{pid(204)}/appRoleAssignedTo",
        body={"principalId": SP_AGENT, "resourceId": pid(204), "appRoleId": MARKER["id"]},
    )
    assert _denied(gate, other).reason is DenyReason.STRIKE_TARGET_NOT_ALLOWED


ASSIGN_ROWS: list[tuple[str, DenyReason, dict[str, Any]]] = [
    (
        "another marker-shaped role",
        DenyReason.BAD_BODY,
        {"appRoleId": pid(499)},
    ),
    ("a real role", DenyReason.BAD_BODY, {"appRoleId": PRE_ROLES[0]["id"]}),
    ("the escalated identity itself", DenyReason.BAD_BODY, {"principalId": SP_ESC}),
    ("Microsoft Graph as the resource", DenyReason.HARD_DENY, {"resourceId": GRAPH_APP_ID}),
]


@pytest.mark.parametrize(("name", "reason", "change"), ASSIGN_ROWS, ids=[r[0] for r in ASSIGN_ROWS])
def test_the_escalated_assignment_body_is_exactly_the_marker(
    name: str, reason: DenyReason, change: dict[str, Any]
) -> None:
    gate, _, _ = escalated_gate(confirm=False)
    roles = [*PRE_ROLES, MARKER, {**MARKER, "id": pid(499)}]  # a second, unlisted marker
    for oid in APPS:
        roles_for = roles if oid == APP_ESC else None
        assert gate.record_lab_check(oid, app_json(oid, roles=roles_for)) is None
    assert gate.record_lab_check(SP_ESC, sp_json()) is None
    good = valid(ASSIGN)
    assert isinstance(good.body, dict)
    d = _denied(gate, replace(good, body={**good.body, **change}))
    assert d.reason is reason, f"{name}: {d.reason} ({d.detail})"


def test_an_escalated_directory_role_assignment_is_a_hard_deny() -> None:
    gate, _, _ = escalated_gate()
    r = req(ASSIGN, "POST", f"{GRAPH}/roleManagement/directory/roleAssignments", {"x": "y"})
    assert _denied(gate, r).reason is DenyReason.HARD_DENY


def test_the_escalated_removal_is_bound_by_the_plan() -> None:
    gate, _, _ = escalated_gate(plan=Exactly(set()))
    assert _denied(gate, valid(UNASSIGN)).reason is DenyReason.NOT_IN_APPROVED_PLAN


# --- forged and invalid scopes ----------------------------------------------------------


def _forged_escalation(**fields: Any) -> ScopeManifest:
    m = strike_manifest()
    assert m.strike is not None
    esc = StrikeEscalation.model_construct(
        **{"service_principal": SP_ESC, "marker_role_id": MARKER["id"], **fields}
    )
    strike = StrikeScope.model_construct(
        expires_at=m.strike.expires_at, targets=m.strike.targets, escalation=esc
    )
    return ScopeManifest.model_construct(**{**m.__dict__, "strike": strike})


@pytest.mark.parametrize(
    "fields",
    [
        {"service_principal": uuid.UUID(SP_AGENT)},  # a test identity
        {"service_principal": uuid.UUID(APP_ESC)},  # an application target
        {"service_principal": uuid.UUID(pid(990))},  # not a target
        {"marker_role_id": uuid.UUID(GRAPH_APP_ID)},  # first party
    ],
    ids=["test identity", "application", "not a target", "first-party marker"],
)
def test_a_forged_escalation_block_denies_everything(fields: dict[str, Any]) -> None:
    for principal in (SP_AGENT, SP_ESC):
        gate, _, _ = write_gate(_forged_escalation(**fields), principal=principal)
        for r in (token_request(), valid(ASSIGN), valid(UNASSIGN)):
            assert _denied(gate, r).reason is DenyReason.NO_MANIFEST


def test_the_model_refuses_the_same_escalation_blocks() -> None:
    agent_sp = {  # a test identity listed as a service principal target, to reach the rule
        "kind": "graph-service-principal",
        "id": SP_AGENT,
        "display_name": "sp-billing-agent",
        "application": APP_ESC,
    }

    def scope(**esc: Any) -> None:
        targets = [*strike_dict()["targets"], agent_sp]
        ScopeManifest.model_validate(
            {
                **strike_manifest().model_dump(mode="json"),
                "strike": strike_dict(
                    targets=targets, escalation={"service_principal": SP_ESC, **esc}
                ),
            }
        )

    scope(marker_role_id=MARKER["id"])  # the valid one
    with pytest.raises(ValidationError, match="never a test identity"):
        scope(marker_role_id=MARKER["id"], service_principal=SP_AGENT)
    with pytest.raises(ValidationError, match="not a target"):
        scope(marker_role_id=MARKER["id"], service_principal=APP_ESC)
    with pytest.raises(ValidationError, match="first-party"):
        scope(marker_role_id=GRAPH_APP_ID)


def test_a_scope_without_escalation_keeps_its_canonical_form() -> None:
    # Scope files rendered before S4 keep their sha256 (plans bind to it).
    s = StrikeScope.model_validate(
        {k: v for k, v in copy.deepcopy(strike_dict()).items() if k != "escalation"}
    )
    assert '"escalation":' not in s.canonical_json()
