"""The write gate, rule by rule (M4 strike plan, "Lab objects only").

Each rule has at least one negative test in ``WRITE_ROWS``. The first test shows
that every form is allowed when everything holds, so the negatives are not passing
just because nothing is ever allowed.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from fns.models.base import sha256_hex
from fns.models.operations import WRITE_FORM_OPERATIONS
from fns.models.scope import ScopeManifest, StrikeScope, StrikeTarget
from fns.scope.gate import (
    Allowed,
    Denied,
    DenyReason,
    FrozenClock,
    Gate,
    InMemoryJournal,
    ScopeDeniedError,
    WriteRequest,
)
from fns.scope.writes import hard_deny
from tests.factories import (
    LATER,
    NOW,
    OTHER_TENANT,
    RG2,
    SP_AGENT,
    SP_VERIFIER,
    TENANT,
    pid,
    scope_dict,
)
from tests.scope.writekit import (
    ADD_OWNER,
    ADD_PASSWORD,
    APP_ESC,
    APP_PATCH,
    APP_VER,
    APPS,
    ARM,
    ASSIGN,
    ASSIGNMENT_ID,
    GRAPH,
    GRAPH_APP_ID,
    INVOICES,
    KV_V,
    LIST_KEYS,
    MARKER,
    MS_SERVICES_TENANT,
    PAYROLL,
    PRE_ROLES,
    REGEN_KEY,
    REMOVE_OWNER,
    REMOVE_PASSWORD,
    SP_ESC,
    STORAGE_V,
    STRIKE_UNTIL,
    TARGETS,
    UNASSIGN,
    VAULT,
    VAULT_WRITE,
    VER_APPID,
    AllowAll,
    Exactly,
    app_json,
    end_time,
    escalated_gate,
    gate_for,
    req,
    sp_json,
    strike_dict,
    strike_manifest,
    valid,
    write_gate,
)

Case = Callable[[], tuple[Gate, WriteRequest]]
NOT_A_REQUEST: Any = "POST /x"


def _ready(op: str) -> tuple[Gate, WriteRequest]:
    gate, _, _ = gate_for(op)
    return gate, valid(op)


# --- liveness -------------------------------------------------------------------------


@pytest.mark.parametrize("op", WRITE_FORM_OPERATIONS)
def test_each_form_is_allowed_when_every_rule_holds(op: str) -> None:
    gate, r = _ready(op)
    d = gate.check_write(r)
    assert isinstance(d, Allowed), d


def test_arm_paths_compare_case_insensitively_like_arm() -> None:
    gate, _, _ = write_gate()
    r = valid(LIST_KEYS)
    upper = replace(r, url=f"{ARM}{PAYROLL.upper()}/LISTKEYS?{STORAGE_V}")
    assert isinstance(gate.check_write(upper), Allowed)


def test_graph_accepts_up_to_seven_fraction_digits_on_the_expiry() -> None:
    gate, _, _ = write_gate()
    end = (NOW + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.1234567Z")
    body = {"passwordCredential": {"displayName": "fns-strike-run-1", "endDateTime": end}}
    assert isinstance(gate.check_write(replace(valid(ADD_PASSWORD), body=body)), Allowed)


# --- the deny table ---------------------------------------------------------------------


def _url(op: str, url: str, **over: Any) -> Case:
    def build() -> tuple[Gate, WriteRequest]:
        gate, r = _ready(op)
        return gate, replace(r, url=url, **over)

    return build


def _body(op: str, body: Any) -> Case:
    def build() -> tuple[Gate, WriteRequest]:
        gate, r = _ready(op)
        return gate, replace(r, body=body)

    return build


def _with(op: str = LIST_KEYS, *, gate: Callable[[], Gate], **over: Any) -> Case:
    def build() -> tuple[Gate, WriteRequest]:
        r = valid(op)
        return gate(), replace(r, **over) if over else r

    return build


def _gate(**kw: Any) -> Callable[[], Gate]:
    return lambda: write_gate(**kw)[0]


def _expired_clock(at: Any) -> Callable[[], Gate]:
    return lambda: write_gate(clock=FrozenClock(at))[0]


def _forged(**fields: Any) -> Callable[[], Gate]:
    def build() -> Gate:
        m = strike_manifest()
        forged = ScopeManifest.model_construct(**{**m.__dict__, **fields})
        return write_gate(forged)[0]

    return build


def _rg2_target() -> Gate:
    m = strike_manifest()
    other = f"{RG2}/providers/Microsoft.Storage/storageAccounts/stpayrolltest"
    strike = m.strike
    assert strike is not None
    forged_target = StrikeTarget.model_construct(kind="arm", id=other)
    forged_strike = StrikeScope.model_construct(
        expires_at=strike.expires_at, targets=(*strike.targets, forged_target)
    )
    return write_gate(ScopeManifest.model_construct(**{**m.__dict__, "strike": forged_strike}))[0]


def _budget_used() -> Gate:
    m = strike_manifest(budget={"max_api_calls": 1, "max_minutes": 60})
    gate, _, _ = write_gate(m)
    gate.call_write(valid(LIST_KEYS), lambda: None)
    return gate


def _time_used() -> Gate:
    gate, _, clock = write_gate()
    clock.advance(3600)
    clock.at = NOW  # wall clock unchanged; only the run's monotonic budget is used up
    return gate


def _no_lab_check() -> Gate:
    return write_gate(confirm=False)[0]


def _escalated_no_lab_check() -> Gate:
    return escalated_gate(confirm=False)[0]


def _escalated_with_roles(**roles: list[dict[str, Any]]) -> Callable[[], Gate]:
    """An escalated gate whose live check read these ``appRoles`` (by app object ID)."""

    def build() -> Gate:
        gate, _, _ = escalated_gate(confirm=False)
        for oid in APPS:
            assert gate.record_lab_check(oid, app_json(oid, roles=roles.get(oid))) is None
        assert gate.record_lab_check(SP_ESC, sp_json()) is None
        return gate

    return build


def _marker_on(app: str) -> Callable[[], Gate]:
    """The marker is defined on another lab app, not on the SP's own."""
    return _escalated_with_roles(**{APP_ESC: PRE_ROLES, app: [*PRE_ROLES, MARKER]})


_marker_disabled = _escalated_with_roles(**{APP_ESC: [*PRE_ROLES, {**MARKER, "isEnabled": False}]})
_marker_not_defined = _escalated_with_roles(**{APP_ESC: PRE_ROLES})
_marker_grants_something = _escalated_with_roles(
    **{APP_ESC: [*PRE_ROLES, {**MARKER, "description": "Admin"}]}
)
_marker_for_users = _escalated_with_roles(
    **{APP_ESC: [*PRE_ROLES, {**MARKER, "allowedMemberTypes": ["User", "Application"]}]}
)


class _Raises:
    def admits(self, request: WriteRequest, body_digest: str) -> bool:
        raise RuntimeError("plan file unreadable")


class _Truthy:
    def admits(self, request: WriteRequest, body_digest: str) -> Any:
        return "yes"


G = GRAPH
A = f"{GRAPH}/applications/{APP_ESC}"
ESC_ASSIGN = f"{GRAPH}/servicePrincipals/{SP_ESC}/appRoleAssignedTo"
PW = {"displayName": "fns-strike-run-1", "endDateTime": end_time()}
ASSIGN_BODY = {"principalId": SP_AGENT, "resourceId": SP_ESC, "appRoleId": MARKER["id"]}
RA_PATH = "providers/Microsoft.Authorization/roleAssignments"
ROLE_CHANGED = {**PRE_ROLES[0], "allowedMemberTypes": ["User", "Application"]}

WRITE_ROWS: list[tuple[str, DenyReason, Case]] = [
    # 1. the hard denylist: before the manifest, whatever it lists
    (
        "directory role assignment",
        DenyReason.HARD_DENY,
        _url(ASSIGN, f"{G}/roleManagement/directory/roleAssignments"),
    ),
    (
        "directoryRoles members",
        DenyReason.HARD_DENY,
        _url(ADD_OWNER, f"{G}/directoryRoles/x/members/$ref"),
    ),
    (
        "encoded roleManagement",
        DenyReason.HARD_DENY,
        _url(ASSIGN, f"{G}/%72oleManagement/directory"),
    ),
    ("double-encoded", DenyReason.HARD_DENY, _url(ASSIGN, f"{G}/%2572oleManagement/directory")),
    ("upper case", DenyReason.HARD_DENY, _url(ASSIGN, f"{G}/ROLEMANAGEMENT/DIRECTORY")),
    (
        "beta roleManagement",
        DenyReason.HARD_DENY,
        _url(ASSIGN, "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments"),
    ),
    ("$batch", DenyReason.HARD_DENY, _url(ASSIGN, "https://graph.microsoft.com/v1.0/$batch")),
    ("oauth2PermissionGrants", DenyReason.HARD_DENY, _url(ASSIGN, f"{G}/oauth2PermissionGrants")),
    (
        "appRoleAssignments (the grant-a-Graph-permission path)",
        DenyReason.HARD_DENY,
        _url(ASSIGN, f"{G}/servicePrincipals/{SP_ESC}/appRoleAssignments"),
    ),
    (
        "federated credential",
        DenyReason.HARD_DENY,
        _url(ADD_PASSWORD, f"{A}/federatedIdentityCredentials"),
    ),
    (
        "ARM role assignment",
        DenyReason.HARD_DENY,
        _url(
            VAULT_WRITE,
            f"{ARM}{VAULT}/providers/Microsoft.Authorization/roleAssignments/{pid(9)}?{KV_V}",
        ),
    ),
    (
        "vault access policy",
        DenyReason.HARD_DENY,
        _url(VAULT_WRITE, f"{ARM}{VAULT}/accessPolicies/add?{KV_V}"),
    ),
    (
        "diagnostic settings (switching off the logs)",
        DenyReason.HARD_DENY,
        _url(VAULT_WRITE, f"{ARM}{VAULT}/providers/Microsoft.Insights/diagnosticSettings/x?{KV_V}"),
    ),
    (
        "Entra diagnostic settings",
        DenyReason.HARD_DENY,
        _url(
            VAULT_WRITE,
            f"{ARM}/providers/microsoft.aadiam/diagnosticSettings/x?api-version=2017-04-01-preview",
        ),
    ),
    (
        "Graph's app ID in the body",
        DenyReason.HARD_DENY,
        _body(ASSIGN, {**ASSIGN_BODY, "resourceId": GRAPH_APP_ID}),
    ),
    (
        "Graph's app ID upper case in the URL",
        DenyReason.HARD_DENY,
        _url(ASSIGN, f"{G}/servicePrincipals(appId='{GRAPH_APP_ID.upper()}')/appRoleAssignedTo"),
    ),
    (
        "Microsoft tenant in the body",
        DenyReason.HARD_DENY,
        _body(REMOVE_PASSWORD, {"keyId": MS_SERVICES_TENANT}),
    ),
    (
        "owner reference to a directory role",
        DenyReason.HARD_DENY,
        _body(ADD_OWNER, {"@odata.id": f"{G}/directoryRoles/{pid(9)}"}),
    ),
    (
        "denylisted operation string",
        DenyReason.HARD_DENY,
        _with(gate=_gate(), operation="graph:POST /roleManagement/directory/roleAssignments"),
    ),
    # 2. manifest, expiry, strike block
    ("no manifest", DenyReason.NO_MANIFEST, _with(gate=_gate(m=None))),
    ("manifest expired", DenyReason.EXPIRED, _with(gate=_expired_clock(LATER))),
    ("strike scope expired", DenyReason.EXPIRED, _with(gate=_expired_clock(STRIKE_UNTIL))),
    (
        "no strike block",
        DenyReason.NO_STRIKE_SCOPE,
        _with(
            gate=_gate(
                m=ScopeManifest.model_validate(
                    scope_dict(allowed_operations={"strike": [LIST_KEYS]})
                )
            )
        ),
    ),
    # 3. tenant
    (
        "request for another tenant",
        DenyReason.TENANT_MISMATCH,
        _with(gate=_gate(), tenant_id=OTHER_TENANT),
    ),
    (
        "signed in to another tenant",
        DenyReason.TENANT_MISMATCH,
        _with(gate=_gate(signed_in=OTHER_TENANT)),
    ),
    # 4. verb and operation
    ("verb harden", DenyReason.VERB_NOT_ALLOWED, _with(gate=_gate(), verb="harden")),
    ("verb scout", DenyReason.VERB_NOT_ALLOWED, _with(gate=_gate(), verb="scout")),
    (
        "operation outside the grammar",
        DenyReason.MALFORMED_OPERATION,
        _with(gate=_gate(), operation="graph:POST applications"),
    ),
    (
        "not a WriteRequest",
        DenyReason.MALFORMED_OPERATION,
        lambda: (write_gate()[0], NOT_A_REQUEST),
    ),
    (
        "a write that is not a form (SP addPassword)",
        DenyReason.NOT_A_WRITE_FORM,
        _with(gate=_gate(), operation="graph:POST /servicePrincipals/{id}/addPassword"),
    ),
    (
        "a read operation",
        DenyReason.NOT_A_WRITE_FORM,
        _with(gate=_gate(), operation="graph:GET /applications"),
    ),
    (
        "a form this scope does not list",
        DenyReason.OPERATION_NOT_ALLOWED,
        _with(gate=_gate(m=strike_manifest(ops=(LIST_KEYS,))), op=REGEN_KEY),
    ),
    # 5. principal
    (
        "signed in as a non-test identity",
        DenyReason.PRINCIPAL_NOT_ALLOWED,
        _with(gate=_gate(principal=SP_VERIFIER)),
    ),
    ("no signed-in principal", DenyReason.PRINCIPAL_NOT_ALLOWED, _with(gate=_gate(principal=None))),
    # 6. method, host, path, query: never normalized into a match
    ("wrong method", DenyReason.BAD_URL, _with(gate=_gate(), method="PUT")),
    ("lower-case method", DenyReason.BAD_URL, _with(gate=_gate(), method="post")),
    (
        "other host",
        DenyReason.BAD_URL,
        _url(LIST_KEYS, f"https://evil.example{PAYROLL}/listKeys?{STORAGE_V}"),
    ),
    (
        "host suffix",
        DenyReason.BAD_URL,
        _url(LIST_KEYS, f"https://management.azure.com.evil.example{PAYROLL}/listKeys?{STORAGE_V}"),
    ),
    (
        "upper-case host",
        DenyReason.BAD_URL,
        _url(LIST_KEYS, f"https://MANAGEMENT.azure.com{PAYROLL}/listKeys?{STORAGE_V}"),
    ),
    (
        "explicit port",
        DenyReason.BAD_URL,
        _url(LIST_KEYS, f"https://management.azure.com:443{PAYROLL}/listKeys?{STORAGE_V}"),
    ),
    (
        "credentials in URL",
        DenyReason.BAD_URL,
        _url(LIST_KEYS, f"https://u:p@management.azure.com{PAYROLL}/listKeys?{STORAGE_V}"),
    ),
    (
        "http",
        DenyReason.BAD_URL,
        _url(LIST_KEYS, f"http://management.azure.com{PAYROLL}/listKeys?{STORAGE_V}"),
    ),
    (
        "ARM host for a Graph form",
        DenyReason.BAD_URL,
        _url(ADD_PASSWORD, f"{ARM}/v1.0/applications/{APP_ESC}/addPassword"),
    ),
    ("trailing slash", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}/addPassword/")),
    (
        "double slash",
        DenyReason.BAD_URL,
        _url(ADD_PASSWORD, f"{GRAPH}/applications//{APP_ESC}/addPassword"),
    ),
    (
        "dot-dot",
        DenyReason.BAD_URL,
        _url(ADD_PASSWORD, f"{GRAPH}/applications/{APP_VER}/../{APP_ESC}/addPassword"),
    ),
    (
        "single dot",
        DenyReason.BAD_URL,
        _url(ADD_PASSWORD, f"{GRAPH}/applications/./{APP_ESC}/addPassword"),
    ),
    (
        "encoded slash",
        DenyReason.BAD_URL,
        _url(ADD_PASSWORD, f"{GRAPH}/applications%2F{APP_ESC}/addPassword"),
    ),
    ("encoded dot", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}/%2E/addPassword")),
    ("semicolon", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}/addPassword;x=1")),
    ("backslash", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}\\addPassword")),
    ("whitespace", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}/addPassword ")),
    ("unicode look-alike", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}/addP\u0430ssword")),
    ("fragment", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}/addPassword#x")),
    (
        "query on a Graph write",
        DenyReason.BAD_URL,
        _url(ADD_PASSWORD, f"{A}/addPassword?$select=id"),
    ),
    ("empty query on a Graph write", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}/addPassword?")),
    (
        "beta",
        DenyReason.BAD_URL,
        _url(ADD_PASSWORD, f"https://graph.microsoft.com/beta/applications/{APP_ESC}/addPassword"),
    ),
    (
        "Graph literal case",
        DenyReason.BAD_URL,
        _url(ADD_PASSWORD, f"{GRAPH}/Applications/{APP_ESC}/addPassword"),
    ),
    ("Graph action case", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}/addpassword")),
    (
        "app slot not a GUID",
        DenyReason.BAD_URL,
        _url(ADD_PASSWORD, f"{GRAPH}/applications/app-escalation-target/addPassword"),
    ),
    ("extra segment", DenyReason.BAD_URL, _url(ADD_PASSWORD, f"{A}/addPassword/x")),
    (
        "'$' outside $ref",
        DenyReason.BAD_URL,
        _url(ADD_OWNER, f"{GRAPH}/applications/{APP_VER}/owners/$count"),
    ),
    ("assignment ID malformed", DenyReason.BAD_URL, _url(UNASSIGN, f"{ESC_ASSIGN}/x")),
    (
        "ARM wrong api-version",
        DenyReason.BAD_URL,
        _url(LIST_KEYS, f"{ARM}{PAYROLL}/listKeys?api-version=2019-06-01"),
    ),
    (
        "ARM extra query",
        DenyReason.BAD_URL,
        _url(LIST_KEYS, f"{ARM}{PAYROLL}/listKeys?{STORAGE_V}&$expand=kerb"),
    ),
    ("ARM no query", DenyReason.BAD_URL, _url(LIST_KEYS, f"{ARM}{PAYROLL}/listKeys")),
    (
        "ARM wrong action",
        DenyReason.BAD_URL,
        _url(LIST_KEYS, f"{ARM}{PAYROLL}/listAccountSas?{STORAGE_V}"),
    ),
    (
        "ARM child path",
        DenyReason.STRIKE_TARGET_NOT_ALLOWED,
        _url(VAULT_WRITE, f"{ARM}{VAULT}/secrets/x?{KV_V}"),
    ),
    # 7. targets: lab objects only, of the right kind, inside the scope
    (
        "app not a target",
        DenyReason.STRIKE_TARGET_NOT_ALLOWED,
        _url(ADD_PASSWORD, f"{GRAPH}/applications/{pid(999)}/addPassword"),
    ),
    (
        "SP in the app slot",
        DenyReason.STRIKE_TARGET_NOT_ALLOWED,
        _url(ADD_PASSWORD, f"{GRAPH}/applications/{SP_ESC}/addPassword"),
    ),
    (
        "app in the SP slot",
        DenyReason.STRIKE_TARGET_NOT_ALLOWED,
        _url(UNASSIGN, f"{GRAPH}/servicePrincipals/{APP_ESC}/appRoleAssignedTo/{ASSIGNMENT_ID}"),
    ),
    (
        "test identity as the app",
        DenyReason.STRIKE_TARGET_NOT_ALLOWED,
        _url(ADD_PASSWORD, f"{GRAPH}/applications/{SP_AGENT}/addPassword"),
    ),
    (
        "storage account not a target",
        DenyReason.STRIKE_TARGET_NOT_ALLOWED,
        _url(LIST_KEYS, f"{ARM}{INVOICES}/listKeys?{STORAGE_V}"),
    ),
    (
        "vault form on a storage account",
        DenyReason.STRIKE_TARGET_NOT_ALLOWED,
        _url(VAULT_WRITE, f"{ARM}{PAYROLL}?{KV_V}"),
    ),
    (
        "removing an owner who is not a test identity",
        DenyReason.STRIKE_TARGET_NOT_ALLOWED,
        _url(REMOVE_OWNER, f"{GRAPH}/applications/{APP_VER}/owners/{SP_VERIFIER}/$ref"),
    ),
    (
        "forged target outside the resource groups",
        DenyReason.RG_NOT_ALLOWED,
        _with(
            gate=_rg2_target,
            url=f"{ARM}{RG2}/providers/Microsoft.Storage/storageAccounts/stpayrolltest/listKeys?{STORAGE_V}",
        ),
    ),
    # 8. the live lab check
    ("app not checked live", DenyReason.LAB_CHECK_FAILED, _with(ADD_PASSWORD, gate=_no_lab_check)),
    (
        "SP not checked live",
        DenyReason.LAB_CHECK_FAILED,
        _with(UNASSIGN, gate=_escalated_no_lab_check),
    ),
    # 9. bodies
    ("listKeys with a body", DenyReason.BAD_BODY, _body(LIST_KEYS, {"expand": "kerb"})),
    ("regenerate key3", DenyReason.BAD_BODY, _body(REGEN_KEY, {"keyName": "kerb1"})),
    ("regenerate no body", DenyReason.BAD_BODY, _body(REGEN_KEY, None)),
    (
        "vault properties",
        DenyReason.BAD_BODY,
        _body(VAULT_WRITE, {"properties": {"enableRbacAuthorization": False}}),
    ),
    (
        "vault tags and properties",
        DenyReason.BAD_BODY,
        _body(VAULT_WRITE, {"tags": {}, "properties": {}}),
    ),
    ("vault tag value not a string", DenyReason.BAD_BODY, _body(VAULT_WRITE, {"tags": {"a": 1}})),
    (
        "vault too many tags",
        DenyReason.BAD_BODY,
        _body(VAULT_WRITE, {"tags": {f"t{i}": "v" for i in range(51)}}),
    ),
    (
        "password lives 2 hours",
        DenyReason.BAD_BODY,
        _body(ADD_PASSWORD, {"passwordCredential": {**PW, "endDateTime": end_time(120)}}),
    ),
    (
        "password already expired",
        DenyReason.BAD_BODY,
        _body(ADD_PASSWORD, {"passwordCredential": {**PW, "endDateTime": end_time(-1)}}),
    ),
    (
        "password with no zone",
        DenyReason.BAD_BODY,
        _body(ADD_PASSWORD, {"passwordCredential": {**PW, "endDateTime": "2026-11-25T12:30:00"}}),
    ),
    (
        "password with an impossible date",
        DenyReason.BAD_BODY,
        _body(ADD_PASSWORD, {"passwordCredential": {**PW, "endDateTime": "2026-11-31T12:30:00Z"}}),
    ),
    (
        "password not named fns-strike-",
        DenyReason.BAD_BODY,
        _body(ADD_PASSWORD, {"passwordCredential": {**PW, "displayName": "backup"}}),
    ),
    (
        "password with a start date",
        DenyReason.BAD_BODY,
        _body(ADD_PASSWORD, {"passwordCredential": {**PW, "startDateTime": end_time(0)}}),
    ),
    (
        "password with secretText",
        DenyReason.BAD_BODY,
        _body(ADD_PASSWORD, {"passwordCredential": {**PW, "secretText": "chosen"}}),
    ),
    (
        "removePassword keyId not a GUID",
        DenyReason.BAD_BODY,
        _body(REMOVE_PASSWORD, {"keyId": "all"}),
    ),
    (
        "app write with more than appRoles",
        DenyReason.BAD_BODY,
        _body(APP_PATCH, {"appRoles": PRE_ROLES, "requiredResourceAccess": []}),
    ),
    (
        "appRoles drops an existing role",
        DenyReason.BAD_BODY,
        _body(APP_PATCH, {"appRoles": [MARKER]}),
    ),
    (
        "appRoles changes an existing role",
        DenyReason.BAD_BODY,
        _body(APP_PATCH, {"appRoles": [ROLE_CHANGED, MARKER]}),
    ),
    (
        "appRoles adds a real role",
        DenyReason.BAD_BODY,
        _body(
            APP_PATCH,
            {"appRoles": [*PRE_ROLES, {**PRE_ROLES[0], "id": pid(402), "value": "Admin"}]},
        ),
    ),
    (
        "two markers",
        DenyReason.BAD_BODY,
        _body(APP_PATCH, {"appRoles": [*PRE_ROLES, MARKER, {**MARKER, "id": pid(403)}]}),
    ),
    (
        "marker for users",
        DenyReason.BAD_BODY,
        _body(APP_PATCH, {"appRoles": [*PRE_ROLES, {**MARKER, "allowedMemberTypes": ["User"]}]}),
    ),
    (
        "marker with another description",
        DenyReason.BAD_BODY,
        _body(APP_PATCH, {"appRoles": [*PRE_ROLES, {**MARKER, "description": "Admin"}]}),
    ),
    (
        "marker with an extra key",
        DenyReason.BAD_BODY,
        _body(APP_PATCH, {"appRoles": [*PRE_ROLES, {**MARKER, "origin": "Application"}]}),
    ),
    (
        "marker reuses a role ID",
        DenyReason.BAD_BODY,
        _body(APP_PATCH, {"appRoles": [*PRE_ROLES, {**MARKER, "id": PRE_ROLES[0]["id"]}]}),
    ),
    (
        "assignment to a non-test principal",
        DenyReason.BAD_BODY,
        _body(ASSIGN, {**ASSIGN_BODY, "principalId": SP_VERIFIER}),
    ),
    (
        "assignment resource differs from the path",
        DenyReason.BAD_BODY,
        _body(ASSIGN, {**ASSIGN_BODY, "resourceId": pid(998)}),
    ),
    (
        "assignment of a real role (SD2)",
        DenyReason.BAD_BODY,
        _body(ASSIGN, {**ASSIGN_BODY, "appRoleId": PRE_ROLES[0]["id"]}),
    ),
    ("assignment with an extra key", DenyReason.BAD_BODY, _body(ASSIGN, {**ASSIGN_BODY, "x": 1})),
    (
        "marker not defined by Terraform on the app (SD2)",
        DenyReason.BAD_BODY,
        _with(ASSIGN, gate=_marker_not_defined),
    ),
    (
        "marker defined on another lab app (SD2)",
        DenyReason.BAD_BODY,
        _with(ASSIGN, gate=_marker_on(APP_VER)),
    ),
    ("marker disabled", DenyReason.BAD_BODY, _with(ASSIGN, gate=_marker_disabled)),
    (
        "marker that may grant something",
        DenyReason.BAD_BODY,
        _with(ASSIGN, gate=_marker_grants_something),
    ),
    ("marker for users too", DenyReason.BAD_BODY, _with(ASSIGN, gate=_marker_for_users)),
    (
        "owner who is not a test identity",
        DenyReason.BAD_BODY,
        _body(ADD_OWNER, {"@odata.id": f"{G}/directoryObjects/{SP_VERIFIER}"}),
    ),
    (
        "owner reference on another host",
        DenyReason.BAD_BODY,
        _body(ADD_OWNER, {"@odata.id": f"https://evil.example/v1.0/directoryObjects/{SP_AGENT}"}),
    ),
    ("DELETE with a body", DenyReason.BAD_BODY, _body(UNASSIGN, {"x": 1})),
    ("body with a float", DenyReason.BAD_BODY, _body(REGEN_KEY, {"keyName": 1.0})),
    ("body not a map", DenyReason.BAD_BODY, _body(REMOVE_PASSWORD, [pid(500)])),
    ("body too large", DenyReason.BAD_BODY, _body(VAULT_WRITE, {"tags": {"a": "x" * 70_000}})),
    # 10. the approved plan
    ("no approved plan", DenyReason.NO_APPROVED_PLAN, _with(gate=_gate(plan=None))),
    (
        "not a step of the plan",
        DenyReason.NOT_IN_APPROVED_PLAN,
        _with(gate=_gate(plan=Exactly(set()))),
    ),
    (
        "plan answers truthy, not True",
        DenyReason.NOT_IN_APPROVED_PLAN,
        _with(gate=_gate(plan=_Truthy())),
    ),
    ("plan raises", DenyReason.INTERNAL_ERROR, _with(gate=_gate(plan=_Raises()))),
    # 11. budget
    ("call budget used", DenyReason.BUDGET_CALLS, _with(gate=_budget_used)),
    ("time budget used", DenyReason.BUDGET_TIME, _with(gate=_time_used)),
]
WRITE_REASONS = {r[1] for r in WRITE_ROWS} | {DenyReason.WRITE_ON_READ_PATH}
"""WRITE_ON_READ_PATH: tests/scope/test_gate_fuzz.py and test_gate_table.py."""


@pytest.mark.parametrize(("name", "reason", "case"), WRITE_ROWS, ids=[r[0] for r in WRITE_ROWS])
def test_write_is_denied(name: str, reason: DenyReason, case: Case) -> None:
    gate, r = case()
    d = gate.check_write(r)
    assert isinstance(d, Denied), f"{name}: allowed"
    assert d.reason is reason, f"{name}: {d.reason} ({d.detail})"


def test_the_denylist_runs_before_the_manifest() -> None:
    gate = Gate(None, signed_in_tenant=TENANT, journal=InMemoryJournal())
    d = gate.check_write(req(ASSIGN, "POST", f"{GRAPH}/roleManagement/directory/roleAssignments"))
    assert isinstance(d, Denied) and d.reason is DenyReason.HARD_DENY


def test_lab_body_text_is_not_denied_by_accident() -> None:
    for op in WRITE_FORM_OPERATIONS:
        r = valid(op)
        assert hard_deny(r.url, [r.operation, r.method, r.body]) is None, op


# --- the live lab check ---------------------------------------------------------------


LAB_ROWS: list[tuple[str, str, Any]] = [
    ("missing lab tag", APP_ESC, app_json(APP_ESC, tags=["project=fang-and-scale"])),
    ("tags as one string", APP_ESC, app_json(APP_ESC, tags="project=fang-and-scale,purpose=lab")),
    ("other display name", APP_ESC, app_json(APP_ESC, displayName="app-escalation-target-2")),
    ("other object", APP_ESC, app_json(APP_ESC, id=pid(999))),
    ("first-party appId", APP_ESC, app_json(APP_ESC, appId=GRAPH_APP_ID)),
    ("no appRoles list", APP_ESC, app_json(APP_ESC, appRoles=None)),
    ("not JSON", APP_ESC, "<html>"),
    ("SP owned by Microsoft's tenant", SP_ESC, sp_json(appOwnerOrganizationId=MS_SERVICES_TENANT)),
    ("SP of another app", SP_ESC, sp_json(appId=VER_APPID)),
    ("SP with Graph's appId", SP_ESC, sp_json(appId=GRAPH_APP_ID)),
]


@pytest.mark.parametrize(("name", "oid", "observed"), LAB_ROWS, ids=[r[0] for r in LAB_ROWS])
def test_lab_check_refuses(name: str, oid: str, observed: Any) -> None:
    gate, _, _ = write_gate(confirm=False)
    for app in APPS:
        if oid == SP_ESC:
            assert gate.record_lab_check(app, app_json(app)) is None
    d = gate.record_lab_check(oid, observed)
    assert isinstance(d, Denied) and d.reason is DenyReason.LAB_CHECK_FAILED, name


def test_lab_check_needs_the_application_before_its_service_principal() -> None:
    gate, _, _ = write_gate(confirm=False)
    d = gate.record_lab_check(SP_ESC, sp_json())
    assert isinstance(d, Denied) and d.reason is DenyReason.LAB_CHECK_FAILED
    assert "application first" in d.detail


def test_lab_check_only_for_targets_and_only_with_a_strike_block() -> None:
    gate, _, _ = write_gate(confirm=False)
    d = gate.record_lab_check(pid(999), app_json(APP_ESC, id=pid(999)))
    assert isinstance(d, Denied) and d.reason is DenyReason.STRIKE_TARGET_NOT_ALLOWED
    plain = ScopeManifest.model_validate(scope_dict())
    gate, _, _ = write_gate(plain, confirm=False)
    d = gate.record_lab_check(APP_ESC, app_json(APP_ESC))
    assert isinstance(d, Denied) and d.reason is DenyReason.NO_STRIKE_SCOPE
    gate, _, _ = write_gate(confirm=False, clock=FrozenClock(STRIKE_UNTIL))
    d = gate.record_lab_check(APP_ESC, app_json(APP_ESC))
    assert isinstance(d, Denied) and d.reason is DenyReason.EXPIRED


def test_the_first_lab_check_is_the_pre_state() -> None:
    # A later read (say, after a crash left a real role behind) cannot redefine
    # what "every existing role stays" means.
    gate, _, _ = write_gate()
    extra = {**PRE_ROLES[0], "id": pid(402), "value": "Admin"}
    assert gate.record_lab_check(APP_ESC, app_json(APP_ESC, roles=[*PRE_ROLES, extra])) is None
    body = {"appRoles": [*PRE_ROLES, extra]}
    d = gate.check_write(replace(valid(APP_PATCH), body=body))
    assert isinstance(d, Denied) and d.reason is DenyReason.BAD_BODY


def test_a_leftover_marker_may_be_disabled_and_removed() -> None:
    gate, _, _ = write_gate(confirm=False)
    left = {**MARKER, "isEnabled": True}
    assert gate.record_lab_check(APP_ESC, app_json(APP_ESC, roles=[*PRE_ROLES, left])) is None
    off = replace(valid(APP_PATCH), body={"appRoles": [*PRE_ROLES, {**left, "isEnabled": False}]})
    assert isinstance(gate.check_write(off), Allowed)
    gone = replace(valid(APP_PATCH), body={"appRoles": copy.deepcopy(PRE_ROLES)})
    assert isinstance(gate.check_write(gone), Allowed)


# --- SD2: the marker role lives only on a lab-created app -------------------------------


def test_sd2_marker_assignment_needs_the_marker_on_the_sps_own_lab_app() -> None:
    gate, _, _ = escalated_gate()
    assert isinstance(gate.check_write(valid(ASSIGN)), Allowed)
    # The same body against any service principal that is not a lab target
    # (Microsoft Graph's, or any first-party one, has a tenant-specific object ID).
    other = replace(valid(ASSIGN), url=f"{GRAPH}/servicePrincipals/{pid(997)}/appRoleAssignedTo")
    d = gate.check_write(other)
    assert isinstance(d, Denied) and d.reason is DenyReason.STRIKE_TARGET_NOT_ALLOWED


def test_sd2_no_scope_can_name_a_first_party_object_as_a_target() -> None:
    for kind in ("graph-application", "graph-service-principal"):
        bad = copy.deepcopy(TARGETS)
        entry: dict[str, Any] = {
            "kind": kind,
            "id": GRAPH_APP_ID,
            "display_name": "Microsoft Graph",
        }
        if kind == "graph-service-principal":
            entry["application"] = APP_ESC
        bad.append(entry)
        with pytest.raises(ValidationError, match="first-party"):
            strike_manifest(strike=strike_dict(targets=bad))


def test_sd2_a_first_party_service_principal_fails_the_lab_check() -> None:
    # Even if a stale scope named its object ID, Microsoft owns the app.
    gate, _, _ = write_gate(confirm=False)
    assert gate.record_lab_check(APP_ESC, app_json(APP_ESC)) is None
    d = gate.record_lab_check(
        SP_ESC, sp_json(appId=GRAPH_APP_ID, appOwnerOrganizationId=MS_SERVICES_TENANT)
    )
    assert isinstance(d, Denied) and d.reason is DenyReason.LAB_CHECK_FAILED


# --- call_write -----------------------------------------------------------------------


def test_call_write_journals_method_and_digest_never_the_body() -> None:
    gate, journal, _ = write_gate()
    r = valid(ADD_PASSWORD)
    assert gate.call_write(r, lambda: "ok") == "ok"
    rec = journal.decisions[-1]
    assert rec.decision == "allowed" and rec.verb == "strike"
    assert (
        rec.detail.startswith("POST body sha256:")
        and len(rec.detail) == len("POST body sha256:") + 64
    )
    assert "fns-strike-run-1" not in repr(rec)
    assert rec.target == f"directory/{APP_ESC}"
    assert journal.results[-1][2] == "succeeded"
    assert gate.calls_used == 1


def test_call_write_denied_never_runs_and_is_journaled() -> None:
    gate, journal, _ = write_gate(plan=None)
    ran: list[int] = []
    with pytest.raises(ScopeDeniedError) as exc:
        gate.call_write(valid(LIST_KEYS), lambda: ran.append(1))
    assert exc.value.decision.reason is DenyReason.NO_APPROVED_PLAN
    assert ran == [] and journal.decisions[-1].decision == "denied"
    assert gate.calls_used == 0


def test_call_write_failure_is_journaled_and_reraised() -> None:
    gate, journal, _ = write_gate()

    def boom() -> None:
        raise TimeoutError

    with pytest.raises(TimeoutError):
        gate.call_write(valid(LIST_KEYS), boom)
    assert journal.results[-1][2:] == ("failed", "TimeoutError")
    assert gate.calls_used == 1


def test_the_plan_sees_the_canonical_body_digest() -> None:
    plan = AllowAll()
    gate, _, _ = write_gate(plan=plan)
    r = valid(REGEN_KEY)
    assert isinstance(gate.check_write(r), Allowed)
    assert plan.seen[-1][1] == sha256_hex('{"keyName":"key1"}')
    exact = Exactly({("POST", r.url, sha256_hex('{"keyName":"key1"}'))})
    gate, _, _ = write_gate(plan=exact)
    assert isinstance(gate.check_write(r), Allowed)
    d = gate.check_write(replace(r, body={"keyName": "key2"}))
    assert isinstance(d, Denied) and d.reason is DenyReason.NOT_IN_APPROVED_PLAN


def test_check_never_allows_a_write_even_with_a_strike_block() -> None:
    gate, _, _ = write_gate()
    d = gate.check("strike", LIST_KEYS, PAYROLL, TENANT, SP_AGENT)
    assert isinstance(d, Denied) and d.reason is DenyReason.WRITE_ON_READ_PATH


# --- the strike block in the model ------------------------------------------------------


def _targets_with(entry: dict[str, Any]) -> list[dict[str, Any]]:
    return [*copy.deepcopy(TARGETS), entry]


MODEL_ROWS: list[tuple[str, dict[str, Any], str]] = [
    (
        "ARM target that is a role assignment",
        {
            "strike": strike_dict(
                targets=_targets_with(
                    {
                        "kind": "arm",
                        "id": f"{PAYROLL}/{RA_PATH}/{pid(9)}",
                    }
                )
            )
        },
        "exactly one vault or storage account",
    ),
    (
        "ARM target that is the resource group",
        {"strike": strike_dict(targets=_targets_with({"kind": "arm", "id": RG2}))},
        "exactly one vault or storage account",
    ),
    (
        "ARM target outside the resource groups",
        {
            "strike": strike_dict(
                targets=_targets_with(
                    {"kind": "arm", "id": f"{RG2}/providers/Microsoft.KeyVault/vaults/kv-x"}
                )
            )
        },
        "outside allowed_resource_groups",
    ),
    (
        "Graph target without a display name",
        {
            "strike": strike_dict(
                targets=_targets_with({"kind": "graph-application", "id": pid(250)})
            )
        },
        "display_name",
    ),
    (
        "SP without its application",
        {
            "strike": strike_dict(
                targets=_targets_with(
                    {"kind": "graph-service-principal", "id": pid(250), "display_name": "x"}
                )
            )
        },
        "names its application",
    ),
    (
        "SP whose application is not a target",
        {
            "strike": strike_dict(
                targets=_targets_with(
                    {
                        "kind": "graph-service-principal",
                        "id": pid(250),
                        "display_name": "x",
                        "application": pid(251),
                    }
                )
            )
        },
        "its application is not a target",
    ),
    (
        "application with an application",
        {
            "strike": strike_dict(
                targets=_targets_with(
                    {
                        "kind": "graph-application",
                        "id": pid(250),
                        "display_name": "x",
                        "application": APP_ESC,
                    }
                )
            )
        },
        "names its application",
    ),
    (
        "duplicate target",
        {"strike": strike_dict(targets=_targets_with({"kind": "arm", "id": PAYROLL.upper()}))},
        "duplicate strike target",
    ),
    (
        "the tenant as a target",
        {
            "strike": strike_dict(
                targets=_targets_with(
                    {"kind": "graph-application", "id": TENANT, "display_name": "x"}
                )
            )
        },
        "tenant itself",
    ),
    (
        "a test identity as an application",
        {
            "strike": strike_dict(
                targets=_targets_with(
                    {"kind": "graph-application", "id": SP_AGENT, "display_name": "x"}
                )
            )
        },
        "cannot be a test identity",
    ),
    (
        "unknown target kind",
        {
            "strike": strike_dict(
                targets=_targets_with({"kind": "graph-group", "id": pid(250), "display_name": "x"})
            )
        },
        "kind",
    ),
    ("no targets", {"strike": strike_dict(targets=[])}, "at least 1"),
    ("naive expiry", {"strike": strike_dict(expires_at="2026-11-25T13:00:00")}, "timezone"),
    (
        "strike lists a directory role write",
        {
            "allowed_operations": {
                "strike": ["graph:POST /roleManagement/directory/roleAssignments"]
            }
        },
        "only the M4 write forms",
    ),
    (
        "strike lists an ARM role assignment write",
        {"allowed_operations": {"strike": ["arm:Microsoft.Authorization/roleAssignments/write"]}},
        "only the M4 write forms",
    ),
]


@pytest.mark.parametrize(("name", "over", "match"), MODEL_ROWS, ids=[r[0] for r in MODEL_ROWS])
def test_strike_block_is_validated(name: str, over: dict[str, Any], match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        strike_manifest(**over)


def test_strike_block_is_canonical_and_optional() -> None:
    m = strike_manifest()
    assert m.strike is not None
    keys = [(t.kind, t.key) for t in m.strike.targets]
    assert keys == sorted(keys)
    plain = ScopeManifest.model_validate(scope_dict())
    assert "strike" not in plain.canonical_json()
    assert (
        m.digest() == strike_manifest(strike=strike_dict(targets=list(reversed(TARGETS)))).digest()
    )
