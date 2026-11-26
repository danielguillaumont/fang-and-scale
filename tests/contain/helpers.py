"""A tiny builder for hand-made snapshots in reach-engine tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fns.fixtures import wellknown as wk
from fns.models.contract import Contract
from fns.models.snapshot import Snapshot
from tests.factories import DA, NOW, RA, SUB, TENANT, pid

SUB_ID = f"/subscriptions/{SUB}"
RG = f"{SUB_ID}/resourceGroups/rg-lab"
KV = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-crown"
ST = f"{RG}/providers/Microsoft.Storage/storageAccounts/stpayroll"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-batch"
GRAPH = pid(900)
AGENT = pid(100)

ROLE_IDS = {
    "Owner": wk.OWNER,
    "Contributor": wk.CONTRIBUTOR,
    "Reader": wk.READER,
    "Storage Blob Data Contributor": wk.STORAGE_BLOB_DATA_CONTRIBUTOR,
    "Key Vault Secrets Officer": wk.KEY_VAULT_SECRETS_OFFICER,
    "User Access Administrator": wk.USER_ACCESS_ADMINISTRATOR,
    "Virtual Machine Contributor": wk.VIRTUAL_MACHINE_CONTRIBUTOR,
}
ROLE_PERMS: dict[str, dict[str, tuple[str, ...]]] = {
    "Owner": {"actions": ("*",)},
    "Contributor": {
        "actions": ("*",),
        "notActions": (
            "Microsoft.Authorization/*/Delete",
            "Microsoft.Authorization/*/Write",
            "Microsoft.Authorization/elevateAccess/Action",
        ),
    },
    "Reader": {"actions": ("*/read",)},
    "Storage Blob Data Contributor": {
        "actions": ("Microsoft.Storage/storageAccounts/blobServices/containers/read",),
        "dataActions": (
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
        ),
    },
    "Key Vault Secrets Officer": {
        "actions": ("Microsoft.KeyVault/vaults/read",),
        "dataActions": ("Microsoft.KeyVault/vaults/secrets/*",),
    },
    "User Access Administrator": {
        "actions": ("*/read", "Microsoft.Authorization/*"),
    },
    "Virtual Machine Contributor": {
        "actions": ("Microsoft.Compute/virtualMachines/*",),
    },
}


def role_def_id(role: str) -> str:
    return f"{SUB_ID}/providers/Microsoft.Authorization/roleDefinitions/{ROLE_IDS[role]}"


def _prov(api: str = "fixture") -> dict[str, Any]:
    return {"source_api": api, "observed_at": NOW.isoformat()}


@dataclass
class Snap:
    """Mutable builder; ``build()`` validates through the real Snapshot model."""

    entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)
    not_collected: list[dict[str, str]] = field(default_factory=list)
    collectors: list[dict[str, Any]] = field(default_factory=list)
    not_applicable: list[dict[str, Any]] = field(default_factory=list)
    _n: int = 0

    def __post_init__(self) -> None:
        self.entity(SUB_ID, "scope", "lab-sub")
        self.entity(RG, "scope", "rg-lab")
        self.entity(GRAPH, "servicePrincipal", "Microsoft Graph", appId=wk.MICROSOFT_GRAPH_APP_ID)
        self.edge("contains", SUB_ID, RG)

    def entity(self, eid: str, etype: str, name: str | None = None, **props: Any) -> str:
        key = eid.lower()
        if key not in self.entities:
            self.entities[key] = {
                "id": eid,
                "type": etype,
                "display_name": name,
                "properties": props,
            }
        return key

    def edge(self, etype: str, src: str, dst: str, **extra: Any) -> Snap:
        self.edges.append({"type": etype, "src": src, "dst": dst, "provenance": _prov(), **extra})
        return self

    def sp(self, n: int, name: str) -> str:
        return self.entity(pid(n), "servicePrincipal", name, appId=pid(n + 5000))

    def app(self, n: int, name: str, sp: str | None = None) -> str:
        a = self.entity(pid(n), "application", name)
        if sp is not None:
            self.edge("instanceOf", sp, a)
        return a

    def resource(self, rid: str, rtype: str, **props: Any) -> str:
        name = rid.rsplit("/", 1)[-1]
        r = self.entity(rid, "resource", name, resourceType=rtype, **props)
        parent = rid.rsplit("/providers/", 1)[0]
        self.entity(parent, "scope")
        self.edge("contains", parent, rid)
        return r

    def kv(self, **props: Any) -> str:
        return self.resource(KV, "Microsoft.KeyVault/vaults", **props)

    def storage(self, rid: str = ST, **props: Any) -> str:
        return self.resource(rid, "Microsoft.Storage/storageAccounts", **props)

    def rbac(self, principal: str, role: str, scope: str, condition: str | None = None) -> Snap:
        rid = role_def_id(role)
        self.entity(rid, "roleDefinition", role, roleType="BuiltInRole", **ROLE_PERMS[role])
        if scope.lower() not in self.entities and scope != "/":
            self.entity(scope, "scope")
        if scope == "/":
            self.entity("/", "scope")
        self._n += 1
        return self.edge(
            "hasRbacRole",
            principal,
            scope.lower() if scope != "/" else "/",
            role_definition_id=rid,
            assignment_id=f"{SUB_ID}/{RA}/{pid(7000 + self._n)}",
            condition=condition,
        )

    def graph_perm(self, principal: str, value: str, role_id: str | None = None) -> Snap:
        self._n += 1
        return self.edge(
            "hasAppRole",
            principal,
            GRAPH,
            app_role_id=role_id or pid(8000 + self._n),
            app_role_value=value,
        )

    def dir_role(self, principal: str, template: str, scope: str = "/") -> Snap:
        self.entity(template, "directoryRole", _DIR_NAMES.get(template, "role"))
        return self.edge("hasDirectoryRole", principal, template, directory_scope_id=scope)

    def deny(self, principal: str, scope: str, actions: tuple[str, ...] = (), **kw: Any) -> Snap:
        self._n += 1
        if principal == "00000000-0000-0000-0000-000000000000":
            self.entity(principal, "group", "Everyone")
        return self.edge(
            "denyAssignment",
            principal,
            scope.lower(),
            deny_assignment_id=f"{scope}/{DA}/{pid(9000 + self._n)}",
            actions=actions,
            **kw,
        )

    def access_policy(self, principal: str, vault: str, secrets: tuple[str, ...]) -> Snap:
        return self.edge("hasAccessPolicy", principal, vault.lower(), secrets=secrets)

    def missing(self, surface: str) -> Snap:
        self.not_collected.append({"surface": surface, "reason": "test"})
        return self

    def build(self) -> Snapshot:
        return Snapshot.model_validate(
            {
                "version": 1,
                "mode": "FIXTURE",
                "tenant_id": TENANT,
                "collected_at": NOW.isoformat(),
                "collector_version": "test",
                "entities": list(self.entities.values()),
                "edges": self.edges,
                "coverage": {
                    "collectors": self.collectors,
                    "not_collected": self.not_collected,
                    "not_applicable": self.not_applicable,
                },
            }
        )


_DIR_NAMES = {
    wk.GLOBAL_ADMINISTRATOR: "Global Administrator",
    wk.PRIVILEGED_ROLE_ADMINISTRATOR: "Privileged Role Administrator",
    wk.APPLICATION_ADMINISTRATOR: "Application Administrator",
    wk.CLOUD_APPLICATION_ADMINISTRATOR: "Cloud Application Administrator",
}


def contract(
    must_not_reach: list[dict[str, Any]],
    must_still_do: list[dict[str, Any]] | None = None,
    who: str = "sp:sp-agent",
    **kw: Any,
) -> Contract:
    v2 = any("application" in i or "service_principal" in i for i in must_not_reach)
    return Contract.model_validate(
        {
            "version": 2 if v2 else 1,
            "contract": "t",
            "assume_compromised": who,
            "must_not_reach": must_not_reach,
            "must_still_do": must_still_do or [],
            **kw,
        }
    )
