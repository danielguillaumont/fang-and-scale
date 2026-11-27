"""Reads for strikes, as ``sp-fns-scout``: pre-state, the live lab check, verification.

A different, read-only identity reads every strike object (M4 strike plan,
"Plan, approval, journal and cleanup", step 5). That way a strike can't verify
its own undo, and the reads still work after harden, when the agent can read
nothing in Graph. Every read is a gated ``scout`` call with the scout's own
operations: the ARM resource reads, and the Graph list endpoints with an ``id``
filter.
"""

from __future__ import annotations

import uuid
from typing import Any, Final, Protocol

from fns.adapters.azure.http import ARM_BASE, GRAPH_BASE, ApiRequest, Transport
from fns.scope.gate import Gate
from fns.scope.targets import ArmTarget, DirectoryTarget
from fns.scope.writes import ARM_API_VERSIONS

OP_STORAGE_READ: Final = "arm:Microsoft.Storage/storageAccounts/read"
OP_VAULT_READ: Final = "arm:Microsoft.KeyVault/vaults/read"
OP_APPLICATIONS: Final = "graph:GET /applications"
OP_SERVICE_PRINCIPALS: Final = "graph:GET /servicePrincipals"
OP_APP_OWNERS: Final = "graph:GET /applications/{id}/owners"
APP_SELECT: Final = "id,appId,displayName,tags,appRoles,passwordCredentials"
SP_SELECT: Final = "id,appId,displayName,tags,appOwnerOrganizationId,appRoles"


class ReadError(RuntimeError):
    """A strike read failed; the strike does not start, or verification fails."""


class LabReader(Protocol):
    def storage_account(self, arm_id: str) -> dict[str, Any]: ...
    def vault(self, arm_id: str) -> dict[str, Any]: ...
    def application(self, object_id: str) -> dict[str, Any]: ...
    def service_principal(self, object_id: str) -> dict[str, Any]: ...
    def app_owners(self, object_id: str) -> list[str]: ...


def _guid(value: str) -> str:
    return str(uuid.UUID(value))


def _by_id(object_id: str) -> str:
    return f"$filter=id%20eq%20%27{_guid(object_id)}%27"


class ScoutReader:
    """:class:`LabReader` through a ``scout`` gate and a read transport."""

    def __init__(self, gate: Gate, transport: Transport, tenant_id: str) -> None:
        self.gate = gate
        self.transport = transport
        self.tenant_id = tenant_id

    def _get(self, request: ApiRequest) -> dict[str, Any]:
        response = self.gate.call(
            "scout",
            request.operation,
            request.target,
            self.tenant_id,
            lambda: self.transport.fetch(request),
            url=request.url,
        )
        if not response.ok:
            raise ReadError(f"{request.operation} returned {response.status}")
        return response.body

    def storage_account(self, arm_id: str) -> dict[str, Any]:
        v = ARM_API_VERSIONS["blob"]
        url = f"{ARM_BASE}{arm_id}?api-version={v}"
        return self._get(ApiRequest("arm", OP_STORAGE_READ, ArmTarget.parse(arm_id), url))

    def vault(self, arm_id: str) -> dict[str, Any]:
        v = ARM_API_VERSIONS["kv"]
        url = f"{ARM_BASE}{arm_id}?api-version={v}"
        return self._get(ApiRequest("arm", OP_VAULT_READ, ArmTarget.parse(arm_id), url))

    def _one(self, op: str, path: str, select: str, object_id: str) -> dict[str, Any]:
        url = f"{GRAPH_BASE}/{path}?{_by_id(object_id)}&$select={select}"
        body = self._get(ApiRequest("graph", op, DirectoryTarget(), url))
        items = body.get("value")
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            raise ReadError(f"{path}: expected exactly one object {object_id}")
        return items[0]

    def application(self, object_id: str) -> dict[str, Any]:
        return self._one(OP_APPLICATIONS, "applications", APP_SELECT, object_id)

    def service_principal(self, object_id: str) -> dict[str, Any]:
        return self._one(OP_SERVICE_PRINCIPALS, "servicePrincipals", SP_SELECT, object_id)

    def app_owners(self, object_id: str) -> list[str]:
        url = f"{GRAPH_BASE}/applications/{_guid(object_id)}/owners?$select=id"
        body = self._get(ApiRequest("graph", OP_APP_OWNERS, DirectoryTarget(), url))
        items = body.get("value")
        if not isinstance(items, list):
            raise ReadError("owners: no value list")
        return sorted(str(i.get("id")).lower() for i in items if isinstance(i, dict))
