"""A fake lab tenant for strike tests: state, write transport, scout read transport.

Placeholder GUIDs only. The storage keys and passwords it returns are made-up
strings that start with ``FAKE-SECRET-``, so a test can scan any output for them.
"""

from __future__ import annotations

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
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal
from fns.strike.plan import ApprovedPlan
from fns.strike.reader import ScoutReader
from fns.strike.transport import StrikeRequest, StrikeTransport
from tests.factories import NOW, SP_AGENT, TENANT, pid, scope_dict
from tests.scope.writekit import (
    APP_ESC,
    APP_SCOUT,
    APP_VER,
    APPS,
    PAYROLL,
    VAULT,
    app_json,
    strike_dict,
)

SECRET_PREFIX = "FAKE-SECRET-"  # noqa: S105 - a made-up marker to scan for
SCOUT = pid(150)
SCOPE_SHA = "a" * 64
SCOUT_READS = [
    "arm:Microsoft.KeyVault/vaults/read",
    "arm:Microsoft.Storage/storageAccounts/read",
    "graph:GET /applications",
    "graph:GET /applications/{id}/owners",
]
ADMIN = pid(160)

Fault = Literal["ok", "500", "403", "raise-before", "raise-after", "crash-before"]


class Crash(BaseException):
    """Stands in for a killed process: not an Exception, so nothing catches it."""


def manifest(ops: tuple[str, ...] = WRITE_FORM_OPERATIONS, **over: Any) -> ScopeManifest:
    data = scope_dict(
        allowed_operations={"strike": list(ops), "scout": SCOUT_READS},
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
    hardened: bool = False
    """After harden: every Graph write by the agent is 403 (D6)."""
    leaky: set[str] = field(default_factory=set)
    """Graph apps where a D-write wrongly succeeds even when hardened."""
    sent: list[StrikeRequest] = field(default_factory=list)
    secrets_issued: list[str] = field(default_factory=list)
    _tick: itertools.count[int] = field(default_factory=lambda: itertools.count(1))
    _ids: itertools.count[int] = field(default_factory=lambda: itertools.count(700))

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(
            {
                "keys": self.key_times,
                "tags": self.vault_tags,
                "creds": self.creds,
                "owners": self.owners,
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

    def apply(self, r: StrikeRequest) -> tuple[int, object]:
        path = urlsplit(r.url).path
        body = r.body if isinstance(r.body, dict) else {}
        if r.api == "arm":
            if path.endswith("/listKeys"):
                return 200, {"keys": self._keys()}
            if path.endswith("/regenerateKey"):
                at = NOW + timedelta(minutes=next(self._tick))
                self.key_times[body["keyName"]] = at.strftime("%Y-%m-%dT%H:%M:%SZ")
                return 200, {"keys": self._keys()}
            self.vault_tags = dict(body["tags"])
            return 200, {"id": VAULT, "tags": self.vault_tags, "properties": {}}
        parts = path.removeprefix("/v1.0/").split("/")
        app = parts[1]
        if self.hardened and app not in self.leaky:
            return 403, {"error": {"code": "Authorization_RequestDenied"}}
        if parts[-1] == "addPassword":
            key_id = pid(next(self._ids))
            name = body["passwordCredential"]["displayName"]
            self.creds[app].append({"keyId": key_id, "displayName": name})
            return 200, {"keyId": key_id, "displayName": name, "secretText": self._secret()}
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
                body = {
                    "id": PAYROLL,
                    "name": "stpayrolltest",
                    "properties": {"keyCreationTime": dict(self.key_times)},
                }
            else:
                body = {"id": VAULT, "name": "kv-crown-jewels", "tags": dict(self.vault_tags)}
            return ApiResponse(200, body)
        if path.endswith("/owners"):
            app = path.split("/")[-2]
            return ApiResponse(200, {"value": [{"id": o} for o in self.owners[app]]})
        flt = unquote(parse_qs(parts.query)["$filter"][0])
        oid = flt.split("'")[1]
        if path.endswith("/applications") and oid in APPS:
            found = app_json(oid, passwordCredentials=copy.deepcopy(self.creds[oid]))
            return ApiResponse(200, {"value": [found]})
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
        status, body = self.tenant.apply(request)
        if fault == "raise-after":
            raise TransportError("read timed out")  # the write happened, the answer is lost
        return status, body, rid


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

    def __post_init__(self) -> None:
        self.reads = FakeReads(self.tenant)

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
