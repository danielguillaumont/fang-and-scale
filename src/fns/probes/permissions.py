"""Rung 2: ``GET {scope}/providers/Microsoft.Authorization/permissions`` as the test identity.

The response lists the caller's effective actions at the scope (one entry per
role assignment; deny assignments are not reflected). An action is ``allowed`` if
some entry grants it and does not exclude it. That is what the platform *says*;
rung 3 decides.

Every request goes through the scope gate under the ``prove`` verb.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any, Final, Literal

from fns.adapters.azure.http import ApiRequest, ApiResponse, Transport, TransportError
from fns.contain.rbac import grants
from fns.models.assertions import ProbeObservation, ProbeSpec
from fns.probes.base import ProbeUnavailableError, observation
from fns.scope.gate import Gate, ScopeDeniedError
from fns.scope.targets import ArmTarget

OPERATION: Final = "arm:Microsoft.Authorization/permissions/read"
API_VERSION: Final = "2022-04-01"
ARM_BASE: Final = "https://management.azure.com"


def permissions_request(scope: str) -> ApiRequest:
    return ApiRequest(
        api="arm",
        operation=OPERATION,
        target=ArmTarget.parse(scope),
        url=f"{ARM_BASE}{scope}/providers/Microsoft.Authorization/permissions"
        f"?api-version={API_VERSION}",
    )


def permits(body: dict[str, Any], action: str, *, data_plane: bool) -> bool:
    entries = body.get("value")
    if not isinstance(entries, list):
        raise ValueError("permissions response has no value list")
    allow_key, deny_key = (
        ("dataActions", "notDataActions") if data_plane else ("actions", "notActions")
    )
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("permissions entry is not an object")
        allowed = [str(a) for a in entry.get(allow_key) or []]
        excluded = [str(a) for a in entry.get(deny_key) or []]
        if grants(allowed, excluded, action):
            return True
    return False


class ArmPermissionsProbe:
    def __init__(
        self,
        *,
        gate: Gate,
        transport: Transport,
        tenant_id: str,
        principal_id: str,
        now: Callable[[], datetime],
        mode: Literal["LIVE", "FIXTURE"] = "LIVE",
    ) -> None:
        self.gate = gate
        self.transport = transport
        self.tenant_id = tenant_id
        self.principal_id = principal_id
        self.now = now
        self.mode: Literal["LIVE", "FIXTURE"] = mode

    def observe(self, spec: ProbeSpec, finding_id: str) -> ProbeObservation:
        if spec.kind != "arm-permissions":
            raise ProbeUnavailableError(f"{spec.kind} is not an arm-permissions probe")
        req = permissions_request(spec.target)

        def fetch() -> ApiResponse:
            return self.transport.fetch(req)

        try:
            resp = self.gate.call(
                "prove",
                req.operation,
                req.target,
                self.tenant_id,
                fetch,
                url=req.url,
                principal_id=self.principal_id,
            )
        except ScopeDeniedError as exc:
            raise ProbeUnavailableError(f"scope denied: {exc.decision.reason.value}") from exc
        except TransportError as exc:
            raise ProbeUnavailableError("transport error") from exc
        if not resp.ok:
            # A failed permissions call says nothing about the action: not a denial.
            return observation(
                spec,
                finding_id,
                mode=self.mode,
                outcome="unknown",
                detail=f"HTTP {resp.status} from the permissions API",
                at=self.now(),
                http_status=resp.status,
                request_id=resp.request_id,
            )
        try:
            ok = permits(resp.body, spec.action, data_plane=spec.data_plane)
        except ValueError as exc:
            raise ProbeUnavailableError(f"bad permissions response: {exc}") from exc
        listed = "listed" if ok else "not listed"
        return observation(
            spec,
            finding_id,
            mode=self.mode,
            outcome="allowed" if ok else "denied",
            detail=f"{spec.action} {listed} in permissions at the scope",
            at=self.now(),
            http_status=resp.status,
            request_id=resp.request_id,
        )
