"""A fake lab tenant for strike tests: state, write transport, scout read transport.

Placeholder GUIDs only. The storage keys, passwords and access tokens it returns
are made-up strings that contain ``FAKE-SECRET-``, so a test can scan any output for
them.

S4: :class:`FakeTokens` answers the token request (only for a password S3 added
that still exists), and :class:`FakeEscalatedWrites` sends with the token it was
given. The marker assignment needs that token: the agent's own transport gets 403.
"""

from __future__ import annotations

import base64
import copy
import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal
from urllib.parse import parse_qs, unquote, urlsplit

from fns.adapters.azure.http import ApiRequest, ApiResponse, TransportError
from fns.journal.sqlite import StrikePhase
from fns.models.operations import WRITE_FORM_OPERATIONS
from fns.models.scope import ScopeManifest
from fns.scope.credentials import TokenProvider
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal
from fns.scope.writes import CAPABILITY_ROLE
from fns.strike.plan import ApprovedPlan
from fns.strike.reader import OP_ASSIGNED_TO, OP_SERVICE_PRINCIPALS, ScoutReader
from fns.strike.run import Escalation
from fns.strike.transport import StrikeRequest, StrikeTransport, TokenTransport, TokenWire
from tests.factories import NOW, SP_AGENT, TENANT, pid, scope_dict
from tests.scope.writekit import (
    APP_ESC,
    APP_SCOUT,
    APP_VER,
    APPS,
    ESC_APPID,
    ESC_ROLES,
    INVOICES_D7,
    PAYROLL,
    SP_ESC,
    VAULT,
    app_json,
    sp_json,
    strike_dict,
)

SECRET_PREFIX = "FAKE-SECRET-"  # noqa: S105 - a made-up marker to scan for
SCOUT = pid(150)
SCOPE_SHA = "a" * 64
RECORDED_SCOUT_READS = [
    "arm:Microsoft.KeyVault/vaults/read",
    "arm:Microsoft.Storage/storageAccounts/read",
    "graph:GET /applications",
    "graph:GET /applications/{id}/owners",
]
"""The scout's reads in the recorded fixture (S1 to S3, D-1 to D-5)."""
SCOUT_READS = sorted([*RECORDED_SCOUT_READS, OP_SERVICE_PRINCIPALS, OP_ASSIGNED_TO])
"""Plus S4's: the escalation SP (its live check) and its app role assignments."""
ADMIN = pid(160)

Fault = Literal["ok", "500", "403", "raise-before", "raise-after", "crash-before"]


class Crash(BaseException):
    """Stands in for a killed process: not an Exception, so nothing catches it."""


def manifest(
    ops: tuple[str, ...] = WRITE_FORM_OPERATIONS,
    scout: list[str] = SCOUT_READS,
    **over: Any,
) -> ScopeManifest:
    data = scope_dict(
        allowed_operations={"strike": list(ops), "scout": list(scout)},
        strike=strike_dict(),
        budget={"max_api_calls": 200, "max_minutes": 60},
    )
    data.update(over)
    return ScopeManifest.model_validate(data)


@dataclass
class FakeTenant:
    key_times: dict[str, str] = field(
        default_factory=lambda: {"key1": "2026-11-01T00:00:00Z", "key2": "2026-11-01T00:00:00Z"}
    )
    invoice_key_times: dict[str, str] = field(
        default_factory=lambda: {"key1": "2026-11-02T00:00:00Z", "key2": "2026-11-02T00:00:00Z"}
    )
    """D-7's account (``INVOICES_D7``)."""
    vault_tags: dict[str, str] = field(
        default_factory=lambda: {"project": "fang-and-scale", "purpose": "lab"}
    )
    creds: dict[str, list[dict[str, Any]]] = field(
        default_factory=lambda: {
            APP_ESC: [{"keyId": pid(600), "displayName": "terraform"}],
            APP_VER: [],
            APP_SCOUT: [{"keyId": pid(601), "displayName": "terraform"}],
        }
    )
    owners: dict[str, list[str]] = field(
        default_factory=lambda: {APP_ESC: [ADMIN], APP_VER: [ADMIN], APP_SCOUT: [ADMIN]}
    )
    storage_tags: dict[str, str] = field(
        default_factory=lambda: {"project": "fang-and-scale", "purpose": "lab"}
    )
    roles: dict[str, list[dict[str, Any]]] = field(
        default_factory=lambda: {APP_ESC: copy.deepcopy(ESC_ROLES)}
    )
    """``appRoles`` by app; the marker is Terraform's, on ``app-escalation-target``."""
    assigned: list[dict[str, str]] = field(
        default_factory=lambda: [
            {
                "id": "fakePreExistingAssign0",
                "principalId": pid(170),
                "appRoleId": ESC_ROLES[0]["id"],
            }
        ]
    )
    """App role assignments on ``app-escalation-target``'s SP."""
    token_claims: dict[str, Any] = field(default_factory=dict)
    """Claims to change on the next token (a test of the capability proof)."""
    token_status: int = 200
    passwords: dict[str, tuple[str, str]] = field(default_factory=dict)
    """Secret text -> (app, keyId), for the token endpoint."""
    tokens: set[str] = field(default_factory=set)
    token_secrets_seen: list[str] = field(default_factory=list)
    hardened: bool = False
    """After harden: every Graph write by the agent is 403 (D6)."""
    leaky: set[str] = field(default_factory=set)
    """Graph apps, or storage account names, where a D-write wrongly succeeds even
    when hardened."""
    sent: list[StrikeRequest] = field(default_factory=list)
    secrets_issued: list[str] = field(default_factory=list)
    _tick: itertools.count[int] = field(default_factory=lambda: itertools.count(1))
    _ids: itertools.count[int] = field(default_factory=lambda: itertools.count(700))

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(
            {
                "keys": self.key_times,
                "invoice_keys": self.invoice_key_times,
                "tags": self.vault_tags,
                "creds": self.creds,
                "owners": self.owners,
                "assigned": self.assigned,
            }
        )

    def _secret(self) -> str:
        s = f"{SECRET_PREFIX}{next(self._ids)}"
        self.secrets_issued.append(s)
        return s

    def _keys(self) -> list[dict[str, str]]:
        return [
            {"keyName": k, "value": self._secret(), "permissions": "FULL"} for k in ("key1", "key2")
        ]

    # -- writes ------------------------------------------------------------------

    # -- S4 ----------------------------------------------------------------------

    def issue_token(self, form: dict[str, str], secret: str) -> tuple[int, object]:
        self.token_secrets_seen.append(secret)
        found = self.passwords.get(secret)
        if (
            found is None
            or found[0] != APP_ESC
            or form.get("client_id") != ESC_APPID
            or not any(c["keyId"] == found[1] for c in self.creds[APP_ESC])
        ):
            return 401, {"error": "invalid_client"}
        if self.token_status != 200:
            return self.token_status, {"error": "temporarily_unavailable"}
        claims: dict[str, Any] = {
            "tid": TENANT,
            "oid": SP_ESC,
            "appid": ESC_APPID,
            "roles": ["Application.Read.All", CAPABILITY_ROLE],
            **self.token_claims,
        }
        claims = {k: v for k, v in claims.items() if v is not None}
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        token = f"eyJhbGciOiJub25lIn0.{payload}.{self._secret()}"
        self.tokens.add(token)
        return 200, {"token_type": "Bearer", "expires_in": 3599, "access_token": token}

    def _assignments(
        self, r: StrikeRequest, parts: list[str], token: str | None
    ) -> tuple[int, object]:
        if parts[1] != SP_ESC:
            return 404, {}
        if token not in self.tokens:
            return 403, {"error": {"code": "Authorization_RequestDenied"}}
        body = r.body if isinstance(r.body, dict) else {}
        if r.method == "POST":
            role_ids = {x["id"] for x in self.roles.get(APP_ESC, [])}
            if body.get("appRoleId") not in role_ids:
                return 400, {"error": {"code": "Request_BadRequest"}}
            a = {
                "id": f"fakeMarkerAssignment{next(self._ids)}",  # Graph-shaped
                "principalId": str(body["principalId"]),
                "appRoleId": str(body["appRoleId"]),
            }
            self.assigned.append(a)
            return 201, {**a, "resourceId": SP_ESC}
        before = len(self.assigned)
        self.assigned = [a for a in self.assigned if a["id"] != parts[3]]
        return (204, {}) if len(self.assigned) < before else (404, {})

    def apply(self, r: StrikeRequest, token: str | None = None) -> tuple[int, object]:
        path = urlsplit(r.url).path
        body = r.body if isinstance(r.body, dict) else {}
        if r.api == "arm":
            account = path.split("/storageAccounts/", 1)[-1].split("/", 1)[0].lower()
            times = self.invoice_key_times if account == "stinvoicesd7" else self.key_times
            if path.endswith("/listKeys"):
                if self.hardened and account not in self.leaky:
                    return 403, {"error": {"code": "AuthorizationFailed"}}
                return 200, {"keys": self._keys()}
            if path.endswith("/regenerateKey"):
                at = NOW + timedelta(minutes=next(self._tick))
                times[body["keyName"]] = at.strftime("%Y-%m-%dT%H:%M:%SZ")
                return 200, {"keys": self._keys()}
            self.vault_tags = dict(body["tags"])
            return 200, {"id": VAULT, "tags": self.vault_tags, "properties": {}}
        parts = path.removeprefix("/v1.0/").split("/")
        app = parts[1]
        if self.hardened and app not in self.leaky:
            return 403, {"error": {"code": "Authorization_RequestDenied"}}
        if parts[0] == "servicePrincipals" and parts[2:3] == ["appRoleAssignedTo"]:
            return self._assignments(r, parts, token)
        if parts[-1] == "addPassword":
            key_id = pid(next(self._ids))
            name = body["passwordCredential"]["displayName"]
            self.creds[app].append({"keyId": key_id, "displayName": name})
            secret = self._secret()
            self.passwords[secret] = (app, key_id)
            return 200, {"keyId": key_id, "displayName": name, "secretText": secret}
        if parts[-1] == "removePassword":
            before = len(self.creds[app])
            self.creds[app] = [c for c in self.creds[app] if c["keyId"] != body["keyId"]]
            return (204, {}) if len(self.creds[app]) < before else (404, {})
        if r.method == "POST" and parts[-1] == "$ref":
            oid = str(body["@odata.id"]).rsplit("/", 1)[-1]
            self.owners[app].append(oid)
            return 204, {}
        if r.method == "DELETE" and parts[-1] == "$ref":
            oid = parts[3]
            if oid not in self.owners[app]:
                return 404, {}
            self.owners[app].remove(oid)
            return 204, {}
        return 400, {"error": {"code": "BadRequest"}}

    # -- reads -------------------------------------------------------------------

    def read(self, request: ApiRequest) -> ApiResponse:
        parts = urlsplit(request.url)
        path = parts.path
        if request.api == "arm":
            if "storageAccounts" in path:
                d7 = "stinvoicesd7" in path.lower()
                body = {
                    "id": INVOICES_D7 if d7 else PAYROLL,
                    "name": "stinvoicesd7" if d7 else "stpayrolltest",
                    "tags": dict(self.storage_tags),
                    "properties": {
                        "keyCreationTime": dict(self.invoice_key_times if d7 else self.key_times)
                    },
                }
            else:
                body = {"id": VAULT, "name": "kv-crown-jewels", "tags": dict(self.vault_tags)}
            return ApiResponse(200, body)
        if path.endswith("/owners"):
            app = path.split("/")[-2]
            return ApiResponse(200, {"value": [{"id": o} for o in self.owners[app]]})
        if path.endswith("/appRoleAssignedTo"):
            sp = path.split("/")[-2]
            found_a = copy.deepcopy(self.assigned) if sp == SP_ESC else []
            return ApiResponse(200, {"value": found_a})
        flt = unquote(parse_qs(parts.query)["$filter"][0])
        oid = flt.split("'")[1]
        if path.endswith("/applications") and oid in APPS:
            found = app_json(
                oid,
                roles=copy.deepcopy(self.roles.get(oid)),
                passwordCredentials=copy.deepcopy(self.creds[oid]),
            )
            return ApiResponse(200, {"value": [found]})
        if path.endswith("/servicePrincipals") and oid == SP_ESC:
            return ApiResponse(200, {"value": [sp_json()]})
        return ApiResponse(200, {"value": []})


class FakeWrites(StrikeTransport):
    """The agent's write transport, with one fault per send (in order)."""

    def __init__(self, tenant: FakeTenant, faults: list[Fault] | None = None) -> None:
        self.tenant = tenant
        self.faults = list(faults or [])
        self.calls = 0
        self.drop: Callable[[StrikeRequest], bool] = lambda r: False

    def _exchange(self, request: StrikeRequest) -> tuple[int, object, str | None]:
        fault = self.faults[self.calls] if self.calls < len(self.faults) else "ok"
        self.calls += 1
        rid = f"req-{self.calls}"
        if fault == "crash-before":
            raise Crash
        if fault == "raise-before":
            raise TransportError("connection reset")
        if fault in ("500", "403"):
            return int(fault), {"error": {"code": "Injected"}}, rid
        self.tenant.sent.append(request)
        if self.drop(request):
            return 204, {}, rid  # says it worked, did nothing (the dropped undo)
        status, body = self.tenant.apply(request, self._token())
        if fault == "raise-after":
            raise TransportError("read timed out")  # the write happened, the answer is lost
        return status, body, rid

    def _token(self) -> str | None:
        return None  # the agent: its own token never holds the marker's permission


class FakeEscalatedWrites(FakeWrites):
    """S4's write transport: every send asks the held token provider first."""

    def __init__(
        self, tenant: FakeTenant, tokens: TokenProvider, faults: list[Fault] | None = None
    ) -> None:
        super().__init__(tenant, faults)
        self.tokens = tokens

    def _token(self) -> str | None:
        return self.tokens.token("graph")


class FakeTokens(TokenTransport):
    """The token endpoint; ``fault`` ``raise-after`` loses the answer."""

    def __init__(self, tenant: FakeTenant, fault: Fault = "ok") -> None:
        self.tenant = tenant
        self.fault = fault
        self.wires: list[TokenWire] = []

    def _exchange_token(self, wire: TokenWire, secret: str) -> tuple[int, object, str | None]:
        self.wires.append(wire)
        if self.fault == "raise-before":
            raise TransportError("connection reset")
        status, body = self.tenant.issue_token(dict(wire.form), secret)
        if self.fault == "raise-after":
            raise TransportError("read timed out")
        return status, body, "token-req-1"


class FakeReads:
    """The scout's read transport."""

    def __init__(self, tenant: FakeTenant) -> None:
        self.tenant = tenant
        self.fetched: list[ApiRequest] = []

    def fetch(self, request: ApiRequest) -> ApiResponse:
        self.fetched.append(request)
        return self.tenant.read(request)


@dataclass
class Lab:
    """Everything a strike run needs, wired to one fake tenant."""

    tenant: FakeTenant = field(default_factory=FakeTenant)
    m: ScopeManifest = field(default_factory=manifest)
    clock: FrozenClock = field(default_factory=lambda: FrozenClock(NOW))
    gate_journal: InMemoryJournal = field(default_factory=InMemoryJournal)
    reads: FakeReads | None = None
    gates: list[Gate] = field(default_factory=list)
    tokens: FakeTokens | None = None
    esc_faults: list[Fault] = field(default_factory=list)
    esc_writes: list[FakeEscalatedWrites] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.reads = FakeReads(self.tenant)
        self.tokens = FakeTokens(self.tenant)

    def reader(self) -> ScoutReader:
        gate = Gate(
            self.m,
            signed_in_tenant=TENANT,
            journal=self.gate_journal,
            clock=self.clock,
            run_id="run-scout",
            signed_in_principal=SCOUT,
        )
        assert self.reads is not None
        return ScoutReader(gate, self.reads, TENANT)

    def gate_factory(self, binding: ApprovedPlan) -> Gate:
        gate = Gate(
            self.m,
            signed_in_tenant=TENANT,
            journal=self.gate_journal,
            clock=self.clock,
            run_id=binding.plan.run_id,
            signed_in_principal=SP_AGENT,
            plan=binding,
        )
        self.gates.append(gate)
        return gate

    def escalated_gate_factory(self, binding: ApprovedPlan, principal: str) -> Gate:
        gate = Gate(
            self.m,
            signed_in_tenant=TENANT,
            journal=self.gate_journal,
            clock=self.clock,
            run_id=binding.plan.run_id,
            signed_in_principal=principal,
            plan=binding,
        )
        self.gates.append(gate)
        return gate

    def escalated_transport(self, tokens: TokenProvider) -> FakeEscalatedWrites:
        w = FakeEscalatedWrites(self.tenant, tokens, self.esc_faults)
        self.esc_writes.append(w)
        return w

    def escalation(self) -> Escalation:
        assert self.tokens is not None
        return Escalation(self.tokens, self.escalated_gate_factory, self.escalated_transport)


@dataclass
class MemoryStrikeJournal:
    """The strike journal's interface in memory (fast fuzzing); rows as JSON text."""

    runs: dict[str, str] = field(default_factory=dict)
    rows: list[tuple[str, str, str, str]] = field(default_factory=list)

    def begin_run(self, run_id: str, verb: str, mode: Literal["LIVE", "FIXTURE"]) -> None:
        assert run_id not in self.runs
        self.runs[run_id] = mode

    def has_run(self, run_id: str) -> bool:
        return run_id in self.runs

    def strike_event(
        self, run_id: str, write_key: str, phase: StrikePhase, detail: dict[str, object]
    ) -> None:
        self.rows.append((run_id, write_key, phase, json.dumps(detail, sort_keys=True)))

    def strike_events(self, run_id: str) -> list[tuple[str, StrikePhase, dict[str, object]]]:
        return [(k, ph, json.loads(d)) for r, k, ph, d in self.rows if r == run_id]  # type: ignore[misc]

    def text(self) -> str:
        return json.dumps(self.rows)
