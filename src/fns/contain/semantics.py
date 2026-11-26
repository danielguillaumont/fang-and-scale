"""What grants each contract operation (docs/milestones/M2.md, "Operation vocabulary").

Contract operations are attacker capabilities. Each one maps to one or more
*ways* it can be granted. An operation, or a resource type, with no entry here
has unknown semantics, and its findings are ``inconclusive``, never ``pass``.

Bump :data:`SEMANTICS_VERSION` whenever a row changes meaning; reports carry it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from fns.fixtures import wellknown as wk

SEMANTICS_VERSION: Final = 2

KEY_VAULT: Final = "microsoft.keyvault/vaults"
STORAGE_ACCOUNT: Final = "microsoft.storage/storageaccounts"

WayKind = Literal["action", "dataAction", "accessPolicy", "appPerm", "dirRole", "ownedObjectPerm"]
Requirement = Literal["kv-rbac-mode", "kv-access-policy-mode", "shared-key"]
TargetKind = Literal["resource", "directory"]

# Graph application permissions the rules and the table care about.
APP_READWRITE_ALL: Final = "Application.ReadWrite.All"
APP_READWRITE_OWNEDBY: Final = "Application.ReadWrite.OwnedBy"
APPROLE_READWRITE_ALL: Final = "AppRoleAssignment.ReadWrite.All"
ROLEMANAGEMENT_READWRITE: Final = "RoleManagement.ReadWrite.Directory"

ROLE_ASSIGNMENTS_WRITE: Final = "Microsoft.Authorization/roleAssignments/write"
KV_WRITE: Final = "Microsoft.KeyVault/vaults/write"
LIST_KEYS: Final = "Microsoft.Storage/storageAccounts/listKeys/action"
_BLOBS: Final = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs"
_SECRETS: Final = "Microsoft.KeyVault/vaults/secrets"

# Pseudo-surface: a collector that did not finish could have missed anything.
INCOMPLETE_COLLECTION: Final = "incomplete-collection"
PIM_ELIGIBILITY: Final = "pim-eligibility"
KV_ACCESS_POLICIES: Final = "key-vault-access-policies"


@dataclass(frozen=True, slots=True)
class Way:
    """One way an operation can be granted."""

    rule: str
    """Label shown on the final hop of a path, e.g. ``kv-control-to-data``."""
    kind: WayKind
    values: tuple[str, ...]
    """ARM (data) actions, Graph app permission values, or directory role template IDs."""
    resource_types: tuple[str, ...] = ()
    """Lowercased ARM types this way applies to; empty means any resource."""
    requires: tuple[Requirement, ...] = ()
    note: str = ""


@dataclass(frozen=True, slots=True)
class OperationSemantics:
    target: TargetKind
    operation: str
    ways: tuple[Way, ...]
    surfaces: tuple[str, ...] = ()
    """``not_collected`` surfaces that could add reach for this operation."""

    def ways_for(self, resource_type: str | None) -> tuple[Way, ...]:
        rtype = (resource_type or "").lower()
        return tuple(w for w in self.ways if not w.resource_types or rtype in w.resource_types)


def _kv_data(op: str, data_action: str, policy: str) -> OperationSemantics:
    return OperationSemantics(
        "resource",
        op,
        (
            Way(
                "rbac-data-action",
                "dataAction",
                (data_action,),
                (KEY_VAULT,),
                ("kv-rbac-mode",),
                "data actions apply only to vaults in RBAC mode",
            ),
            Way(
                "access-policy",
                "accessPolicy",
                (policy, "all"),
                (KEY_VAULT,),
                ("kv-access-policy-mode",),
                "access policies apply only to vaults in access-policy mode",
            ),
            Way(
                "kv-control-to-data",
                "action",
                (KV_WRITE,),
                (KEY_VAULT,),
                note=(
                    "vaults/write can switch the vault to access-policy mode or add an "
                    "access policy; whether newer API versions also demand "
                    "roleAssignments/write for the switch is an M3 probe"
                ),
            ),
        ),
        (KV_ACCESS_POLICIES,),
    )


def _blob(op: str, data_actions: tuple[str, ...]) -> OperationSemantics:
    return OperationSemantics(
        "resource",
        op,
        (
            Way("rbac-data-action", "dataAction", data_actions, (STORAGE_ACCOUNT,)),
            Way(
                "listkeys-data",
                "action",
                (LIST_KEYS,),
                (STORAGE_ACCOUNT,),
                ("shared-key",),
                "the account key grants full data-plane access",
            ),
        ),
    )


_TABLE: Final[tuple[OperationSemantics, ...]] = (
    _kv_data("secrets/get", f"{_SECRETS}/getSecret/action", "get"),
    _kv_data("secrets/list", f"{_SECRETS}/readMetadata/action", "list"),
    _kv_data("secrets/set", f"{_SECRETS}/setSecret/action", "set"),
    OperationSemantics(
        "resource", "listKeys", (Way("rbac-action", "action", (LIST_KEYS,), (STORAGE_ACCOUNT,)),)
    ),
    _blob("blob/read", (f"{_BLOBS}/read",)),
    _blob("blob/write", (f"{_BLOBS}/write", f"{_BLOBS}/add/action")),
    OperationSemantics(
        "resource",
        "roleAssignments/write",
        (Way("rbac-action", "action", (ROLE_ASSIGNMENTS_WRITE,)),),
    ),
    OperationSemantics(
        "directory",
        "roleAssignments/write",
        (
            Way("graph-permission", "appPerm", (ROLEMANAGEMENT_READWRITE,)),
            Way(
                "directory-role",
                "dirRole",
                (wk.GLOBAL_ADMINISTRATOR, wk.PRIVILEGED_ROLE_ADMINISTRATOR),
            ),
        ),
    ),
    OperationSemantics(
        "directory",
        "applications/credentials/update",
        (
            Way("graph-permission", "appPerm", (APP_READWRITE_ALL,)),
            Way(
                "owned-object-permission",
                "ownedObjectPerm",
                (APP_READWRITE_OWNEDBY, APP_READWRITE_ALL),
                note="owner of at least one application or service principal",
            ),
            Way(
                "directory-role",
                "dirRole",
                (
                    wk.GLOBAL_ADMINISTRATOR,
                    wk.APPLICATION_ADMINISTRATOR,
                    wk.CLOUD_APPLICATION_ADMINISTRATOR,
                ),
            ),
        ),
    ),
    OperationSemantics(
        "directory",
        "appRoleAssignments/write",
        (
            Way("graph-permission", "appPerm", (APPROLE_READWRITE_ALL,)),
            Way(
                "directory-role",
                "dirRole",
                (wk.GLOBAL_ADMINISTRATOR, wk.PRIVILEGED_ROLE_ADMINISTRATOR),
            ),
        ),
    ),
)

TABLE: Final[dict[tuple[str, str], OperationSemantics]] = {
    (s.target, s.operation.lower()): s for s in _TABLE
}

GLOBAL_SURFACES: Final = (PIM_ELIGIBILITY,)
"""Surfaces that could add reach to any operation."""


def lookup(target: TargetKind, operation: str) -> OperationSemantics | None:
    return TABLE.get((target, operation.lower()))


def graph_permissions_in_use() -> frozenset[str]:
    """Graph app permissions any rule or table row depends on (self-grant targets)."""
    values = {APP_READWRITE_ALL, APP_READWRITE_OWNEDBY, APPROLE_READWRITE_ALL}
    values.add(ROLEMANAGEMENT_READWRITE)
    for sem in _TABLE:
        for way in sem.ways:
            if way.kind in {"appPerm", "ownedObjectPerm"}:
                values.update(way.values)
    return frozenset(values)
