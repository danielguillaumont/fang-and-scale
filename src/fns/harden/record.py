"""Record mode: turn exported log rows into ``must_still_do`` items (M4 K2).

Input is Log Analytics rows exported as JSON (an array of objects with ``Type``).
Only successful rows performed by the recorded identity count. Unknown operations
are reported as ``unmapped``, never dropped silently. Directory operations are
reported but not written: contract v1 ``must_still_do`` holds resource targets
only (H3). Targets are written by resource name, never ARM ID (H4).
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from fns.models.contract import Contract

BLOB_OPS: Final[dict[str, str]] = {
    "getblob": "blob/read",
    "getblobproperties": "blob/read",
    "putblob": "blob/write",
    "putblock": "blob/write",
    "putblocklist": "blob/write",
    "appendblock": "blob/write",
}
KV_OPS: Final[dict[str, str]] = {
    "secretget": "secrets/get",
    "secretlist": "secrets/list",
    "secretset": "secrets/set",
}
ACTIVITY_OPS: Final[dict[str, str]] = {
    "microsoft.storage/storageaccounts/listkeys/action": "listKeys",
    "microsoft.authorization/roleassignments/write": "roleAssignments/write",
}
_EN_DASH: Final = chr(0x2013)  # Entra writes this activity name with an en dash
AUDIT_OPS: Final[dict[str, str]] = {
    f"update application {_EN_DASH} certificates and secrets management": (
        "applications/credentials/update"
    ),
    "update application - certificates and secrets management": "applications/credentials/update",
    "add app role assignment to service principal": "appRoleAssignments/write",
    "add member to role": "roleAssignments/write",
}


class RecordError(ValueError):
    pass


@dataclass(frozen=True, slots=True, order=True)
class Recorded:
    resource: str
    """Resource name (last ARM ID segment), or ``tenant`` for directory operations."""
    operation: str
    table: str


@dataclass
class Recording:
    resource_ops: set[Recorded] = field(default_factory=set)
    directory_ops: set[Recorded] = field(default_factory=set)
    unmapped: Counter[str] = field(default_factory=Counter)
    failed: int = 0
    other_identity: int = 0
    rows: int = 0


def _lower(row: dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = row.get(k)
        if isinstance(v, str) and v:
            return v.lower()
    return ""


def _name(resource_id: str) -> str:
    return resource_id.rstrip("/").rsplit("/", 1)[-1]


def _account(resource_id: str) -> str:
    """``.../storageaccounts/<name>/blobservices/default`` -> ``<name>``."""
    parts = resource_id.split("/")
    if "storageaccounts" in parts and parts.index("storageaccounts") + 1 < len(parts):
        return parts[parts.index("storageaccounts") + 1]
    return _name(resource_id)


def _caller(row: dict[str, Any], table: str) -> str:
    if table == "StorageBlobLogs":
        return _lower(row, "RequesterObjectId")
    if table == "AzureDiagnostics":
        return _lower(
            row,
            "identity_claim_oid_g",
            "identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g",
        )
    if table == "AzureActivity":
        return _lower(row, "Caller")
    if table == "AuditLogs":
        initiated = row.get("InitiatedBy")
        if isinstance(initiated, str):
            try:
                initiated = json.loads(initiated)
            except json.JSONDecodeError:
                return ""
        if isinstance(initiated, dict):
            app = initiated.get("app") or {}
            return str(app.get("servicePrincipalId") or "").lower()
    return ""


def _succeeded(row: dict[str, Any], table: str) -> bool:
    if table == "StorageBlobLogs":
        return str(row.get("StatusCode", "")).startswith("2")
    if table == "AzureDiagnostics":
        return _lower(row, "ResultSignature") == "ok" or str(
            row.get("httpStatusCode_d", "")
        ).startswith("2")
    if table == "AzureActivity":
        return _lower(row, "ActivityStatusValue") in {"success", "succeeded"}
    if table == "AuditLogs":
        return _lower(row, "Result") == "success"
    return False


def record(rows: list[dict[str, Any]], identity: str) -> Recording:
    rec = Recording()
    who = identity.lower()
    for row in rows:
        if not isinstance(row, dict):
            raise RecordError("each log row must be an object")
        rec.rows += 1
        table = str(row.get("Type", ""))
        if table == "StorageBlobLogs":
            op = BLOB_OPS.get(_lower(row, "OperationName"))
            resource = _lower(row, "AccountName") or _account(_lower(row, "_ResourceId"))
        elif (
            table == "AzureDiagnostics" and _lower(row, "ResourceProvider") == "microsoft.keyvault"
        ):
            op = KV_OPS.get(_lower(row, "OperationName"))
            resource = _name(_lower(row, "_ResourceId", "ResourceId"))
        elif table == "AzureActivity":
            op = ACTIVITY_OPS.get(_lower(row, "OperationNameValue"))
            resource = _name(_lower(row, "_ResourceId", "ResourceId"))
            if op == "roleAssignments/write":
                # An RBAC write at a scope: record against the scope, not the assignment.
                rid = _lower(row, "_ResourceId", "ResourceId")
                resource = _name(rid.split("/providers/microsoft.authorization/")[0])
        elif table == "AuditLogs":
            op = AUDIT_OPS.get(_lower(row, "OperationName", "ActivityDisplayName"))
            resource = "tenant"
        else:
            rec.unmapped[f"{table or '?'}"] += 1
            continue
        if op is None:
            name = _lower(row, "OperationName", "OperationNameValue", "ActivityDisplayName")
            rec.unmapped[f"{table}:{name}"] += 1
            continue
        if _caller(row, table) != who:
            rec.other_identity += 1
            continue
        if not _succeeded(row, table):
            rec.failed += 1
            continue
        item = Recorded(resource, op, table)
        (rec.directory_ops if resource == "tenant" else rec.resource_ops).add(item)
    return rec


def load_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        try:
            data = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise RecordError(f"{path.name}: {exc}") from exc
        if not isinstance(data, list):
            raise RecordError(f"{path.name}: expected a JSON array of log rows")
        rows.extend(data)
    return rows


def still_do_items(rec: Recording) -> list[dict[str, Any]]:
    by_resource: dict[str, set[str]] = {}
    for r in rec.resource_ops:
        by_resource.setdefault(r.resource, set()).add(r.operation)
    return [
        {"resource": name, "operations": sorted(ops), "source": "recorded"}
        for name, ops in sorted(by_resource.items())
    ]


@dataclass(frozen=True, slots=True)
class Merge:
    contract: Contract
    added: tuple[str, ...]
    already: tuple[str, ...]
    conflicts: tuple[str, ...]
    """``resource operation`` pairs that are also in must_not_reach: left out."""


def merge(contract: Contract, rec: Recording) -> Merge:
    data = contract.model_dump(mode="json")
    forbidden = {
        (str(i.get("resource", "")).lower(), op.lower())
        for i in data["must_not_reach"]
        for op in i["operations"]
    }
    existing = {
        (str(i["resource"]).lower(), op.lower())
        for i in data["must_still_do"]
        for op in i["operations"]
    }
    added, already, conflicts = [], [], []
    new_items: dict[str, set[str]] = {}
    for r in sorted(rec.resource_ops):
        key = (r.resource.lower(), r.operation.lower())
        label = f"{r.resource} {r.operation}"
        if key in forbidden:
            conflicts.append(label)
        elif key in existing:
            already.append(label)
        else:
            new_items.setdefault(r.resource, set()).add(r.operation)
            added.append(label)
    data["must_still_do"] = [
        *data["must_still_do"],
        *(
            {"resource": n, "operations": sorted(ops), "source": "recorded"}
            for n, ops in sorted(new_items.items())
        ),
    ]
    try:
        merged = Contract.model_validate(data)
    except ValidationError as exc:
        raise RecordError(f"merged contract is invalid: {exc.error_count()} error(s)") from exc
    return Merge(merged, tuple(added), tuple(already), tuple(conflicts))
