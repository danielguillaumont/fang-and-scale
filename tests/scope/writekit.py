"""Shared builders for write-gate tests (M4 strike plan). Placeholder GUIDs only."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import Any

from fns.models.operations import WRITE_FORM_OPERATIONS
from fns.models.scope import ScopeManifest
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal, WriteRequest
from tests.factories import KV, NOW, RG, SP_AGENT, TENANT, pid, scope_dict

APP_ESC = pid(200)
SP_ESC = pid(201)
APP_VER = pid(202)
APP_SCOUT = pid(203)
ESC_APPID = pid(300)
VER_APPID = pid(301)
SCOUT_APPID = pid(302)
PAYROLL = f"{RG}/providers/Microsoft.Storage/storageAccounts/stpayrolltest"
INVOICES = f"{RG}/providers/Microsoft.Storage/storageAccounts/stinvoicestest"
VAULT = KV
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph (public)
MS_SERVICES_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"  # public
STRIKE_UNTIL = NOW + timedelta(hours=1)

(
    LIST_KEYS,
    REGEN_KEY,
    VAULT_WRITE,
    ADD_PASSWORD,
    REMOVE_PASSWORD,
    APP_PATCH,
    ASSIGN,
    UNASSIGN,
    ADD_OWNER,
    REMOVE_OWNER,
) = WRITE_FORM_OPERATIONS

ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com/v1.0"
STORAGE_V = "api-version=2023-05-01"
KV_V = "api-version=2023-07-01"
ASSIGNMENT_ID = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ab"

PRE_ROLES: list[dict[str, Any]] = [
    {
        "allowedMemberTypes": ["Application"],
        "description": "Read invoices",
        "displayName": "Invoices.Read",
        "id": pid(400),
        "isEnabled": True,
        "origin": "Application",
        "value": "Invoices.Read",
    }
]
MARKER: dict[str, Any] = {
    "id": pid(401),
    "value": "fns.strike.marker",
    "allowedMemberTypes": ["Application"],
    "isEnabled": True,
    "displayName": "Fang & Scale strike marker run-1",
    "description": "Grants nothing",
}
ESC_ROLES: list[dict[str, Any]] = [*PRE_ROLES, MARKER]
"""``app-escalation-target``'s roles: the marker is defined by Terraform (S4)."""
ESCALATION: dict[str, Any] = {"service_principal": SP_ESC, "marker_role_id": MARKER["id"]}

TARGETS: list[dict[str, Any]] = [
    {"kind": "arm", "id": PAYROLL},
    {"kind": "arm", "id": VAULT},
    {"kind": "graph-application", "id": APP_ESC, "display_name": "app-escalation-target"},
    {"kind": "graph-application", "id": APP_VER, "display_name": "id-verifier"},
    {"kind": "graph-application", "id": APP_SCOUT, "display_name": "sp-fns-scout"},
    {
        "kind": "graph-service-principal",
        "id": SP_ESC,
        "display_name": "app-escalation-target",
        "application": APP_ESC,
    },
]
APPS = {
    APP_ESC: ("app-escalation-target", ESC_APPID),
    APP_VER: ("id-verifier", VER_APPID),
    APP_SCOUT: ("sp-fns-scout", SCOUT_APPID),
}


def strike_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "expires_at": STRIKE_UNTIL.isoformat(),
        "targets": copy.deepcopy(TARGETS),
        "escalation": copy.deepcopy(ESCALATION),
    }
    base.update(overrides)
    return base


def strike_manifest(
    ops: tuple[str, ...] = WRITE_FORM_OPERATIONS, **overrides: Any
) -> ScopeManifest:
    data = scope_dict(
        allowed_operations={"strike": list(ops)},
        strike=strike_dict(),
        budget={"max_api_calls": 100, "max_minutes": 60},
    )
    data.update(overrides)
    return ScopeManifest.model_validate(data)


def app_json(oid: str, roles: list[dict[str, Any]] | None = None, **over: Any) -> dict[str, Any]:
    name, app_id = APPS[oid]
    body: dict[str, Any] = {
        "id": oid,
        "appId": app_id,
        "displayName": name,
        "tags": ["project=fang-and-scale", "purpose=lab"],
        "appRoles": copy.deepcopy(
            (ESC_ROLES if oid == APP_ESC else PRE_ROLES) if roles is None else roles
        ),
    }
    body.update(over)
    return body


def sp_json(**over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": SP_ESC,
        "appId": ESC_APPID,
        "displayName": "app-escalation-target",
        "appOwnerOrganizationId": TENANT,
        "tags": [
            "WindowsAzureActiveDirectoryIntegratedApp",
            "project=fang-and-scale",
            "purpose=lab",
        ],
    }
    body.update(over)
    return body


@dataclass
class AllowAll:
    """A plan binding that admits every request (the plan PR adds the real one)."""

    seen: list[tuple[WriteRequest, str]] = field(default_factory=list)

    def admits(self, request: WriteRequest, body_digest: str) -> bool:
        self.seen.append((request, body_digest))
        return True


@dataclass
class Exactly:
    """Admits only the listed (method, url, digest) steps."""

    steps: set[tuple[str, str, str]]

    def admits(self, request: WriteRequest, body_digest: str) -> bool:
        return (request.method, request.url, body_digest) in self.steps


_DEFAULT: Any = object()


def write_gate(
    m: Any = _DEFAULT,
    *,
    plan: Any = _DEFAULT,
    confirm: bool = True,
    principal: str | None = SP_AGENT,
    signed_in: str = TENANT,
    clock: FrozenClock | None = None,
    journal: InMemoryJournal | None = None,
) -> tuple[Gate, InMemoryJournal, FrozenClock]:
    clock = clock or FrozenClock(NOW)
    journal = journal or InMemoryJournal()
    gate = Gate(
        strike_manifest() if m is _DEFAULT else m,
        signed_in_tenant=signed_in,
        journal=journal,
        clock=clock,
        run_id="run-write",
        signed_in_principal=principal,
        plan=AllowAll() if plan is _DEFAULT else plan,
    )
    if confirm:
        for oid in APPS:
            gate.record_lab_check(oid, app_json(oid))
        gate.record_lab_check(SP_ESC, sp_json())
    return gate, journal, clock


def req(op: str, method: str, url: str, body: Any = None, **over: Any) -> WriteRequest:
    r = WriteRequest(
        verb="strike", operation=op, method=method, url=url, body=body, tenant_id=TENANT
    )
    return replace(r, **over)


def end_time(minutes: int = 60) -> str:
    return (NOW + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def valid(op: str) -> WriteRequest:
    """The one well-formed request for each form, against the lab targets."""
    return {
        LIST_KEYS: req(LIST_KEYS, "POST", f"{ARM}{PAYROLL}/listKeys?{STORAGE_V}"),
        REGEN_KEY: req(
            REGEN_KEY, "POST", f"{ARM}{PAYROLL}/regenerateKey?{STORAGE_V}", {"keyName": "key1"}
        ),
        VAULT_WRITE: req(
            VAULT_WRITE,
            "PATCH",
            f"{ARM}{VAULT}?{KV_V}",
            {"tags": {"project": "fang-and-scale", "purpose": "lab", "fns-strike": "run-1"}},
        ),
        ADD_PASSWORD: req(
            ADD_PASSWORD,
            "POST",
            f"{GRAPH}/applications/{APP_ESC}/addPassword",
            {"passwordCredential": {"displayName": "fns-strike-run-1", "endDateTime": end_time()}},
        ),
        REMOVE_PASSWORD: req(
            REMOVE_PASSWORD,
            "POST",
            f"{GRAPH}/applications/{APP_ESC}/removePassword",
            {"keyId": pid(500)},
        ),
        APP_PATCH: req(
            APP_PATCH,
            "PATCH",
            f"{GRAPH}/applications/{APP_ESC}",
            {"appRoles": [*copy.deepcopy(PRE_ROLES), copy.deepcopy(MARKER)]},
        ),
        ASSIGN: req(
            ASSIGN,
            "POST",
            f"{GRAPH}/servicePrincipals/{SP_ESC}/appRoleAssignedTo",
            {"principalId": SP_AGENT, "resourceId": SP_ESC, "appRoleId": MARKER["id"]},
        ),
        UNASSIGN: req(
            UNASSIGN,
            "DELETE",
            f"{GRAPH}/servicePrincipals/{SP_ESC}/appRoleAssignedTo/{ASSIGNMENT_ID}",
        ),
        ADD_OWNER: req(
            ADD_OWNER,
            "POST",
            f"{GRAPH}/applications/{APP_VER}/owners/$ref",
            {"@odata.id": f"{GRAPH}/directoryObjects/{SP_AGENT}"},
        ),
        REMOVE_OWNER: req(
            REMOVE_OWNER, "DELETE", f"{GRAPH}/applications/{APP_VER}/owners/{SP_AGENT}/$ref"
        ),
    }[op]


def escalated_gate(m: Any = _DEFAULT, **kw: Any) -> tuple[Gate, InMemoryJournal, FrozenClock]:
    """A write gate signed in as ``app-escalation-target`` (S4's token ``oid``)."""
    return write_gate(m, principal=SP_ESC, **kw)


ESCALATED_FORMS = (ASSIGN, UNASSIGN)
"""What the escalated identity may send, and nobody else may."""


def gate_for(op: str, **kw: Any) -> tuple[Gate, InMemoryJournal, FrozenClock]:
    """The gate that may send ``op`` when every rule holds."""
    return escalated_gate(**kw) if op in ESCALATED_FORMS else write_gate(**kw)
