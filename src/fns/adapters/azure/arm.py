"""ARM request catalogue and pure response parsers.

No I/O here: requests are data, parsers turn raw JSON into builder facts. The
collector runs every request through the scope gate.
"""

from __future__ import annotations

from typing import Any, Final

from fns.adapters.azure.http import ARM_BASE, ApiRequest
from fns.inventory.builder import PRIORITY_PRIMARY, PRIORITY_STUB, SnapshotBuilder
from fns.models.armid import GUID_RE, ArmIdError, parse_arm_id
from fns.models.snapshot import EVERYONE_PRINCIPAL_ID, TENANT_ROOT_SCOPE, EntityType, Provenance
from fns.scope.targets import ArmTarget

AUTHZ_API: Final = "2022-04-01"
RESOURCES_API: Final = "2021-04-01"

OP_ROLE_ASSIGNMENTS: Final = "arm:Microsoft.Authorization/roleAssignments/read"
OP_ROLE_DEFINITIONS: Final = "arm:Microsoft.Authorization/roleDefinitions/read"
OP_DENY_ASSIGNMENTS: Final = "arm:Microsoft.Authorization/denyAssignments/read"
OP_RG_RESOURCES: Final = "arm:Microsoft.Resources/subscriptions/resourceGroups/resources/read"
OP_KEY_VAULT: Final = "arm:Microsoft.KeyVault/vaults/read"
OP_STORAGE_ACCOUNT: Final = "arm:Microsoft.Storage/storageAccounts/read"
KEY_VAULT_API: Final = "2023-07-01"
STORAGE_API: Final = "2023-05-01"

ARM_OPERATIONS: Final = (
    OP_ROLE_ASSIGNMENTS,
    OP_ROLE_DEFINITIONS,
    OP_DENY_ASSIGNMENTS,
    OP_RG_RESOURCES,
)

SETTINGS_OPERATIONS: Final = (OP_KEY_VAULT, OP_STORAGE_ACCOUNT)
"""Per-resource reads for settings the reach model needs (M2 C1). Optional: a scope
that does not allow them leaves those settings uncollected (and says so)."""

OP_ROLE_ELIGIBILITY: Final = "arm:Microsoft.Authorization/roleEligibilitySchedules/read"
PIM_API: Final = "2020-10-01"
PIM_OPERATIONS: Final = (OP_ROLE_ELIGIBILITY,)
"""Azure resource PIM eligibility (M3 E1). Optional, like the settings reads."""

SETTINGS_TYPES: Final[dict[str, str]] = {
    "microsoft.keyvault/vaults": OP_KEY_VAULT,
    "microsoft.storage/storageaccounts": OP_STORAGE_ACCOUNT,
}

PRINCIPAL_TYPES: Final[dict[str, EntityType]] = {
    "User": "user",
    "Group": "group",
    "ForeignGroup": "group",
    "ServicePrincipal": "servicePrincipal",
}


class ParseError(ValueError):
    """A response that does not have the documented shape."""


def _req(op: str, target_id: str, path: str, api_version: str) -> ApiRequest:
    return ApiRequest(
        api="arm",
        operation=op,
        target=ArmTarget.parse(target_id),
        url=f"{ARM_BASE}{path}?api-version={api_version}",
    )


def role_assignments_request(subscription_id: str) -> ApiRequest:
    sub = f"/subscriptions/{subscription_id}"
    return _req(
        OP_ROLE_ASSIGNMENTS,
        sub,
        f"{sub}/providers/Microsoft.Authorization/roleAssignments",
        AUTHZ_API,
    )


def role_definition_request(subscription_id: str, role_definition_guid: str) -> ApiRequest:
    """Fetch a definition through the subscription it was referenced from.

    ARM resolves any definition assignable at that subscription (built-in, or
    custom from a parent management group), so the request never needs a
    management-group target, which the M1 gate denies.
    """
    sub = f"/subscriptions/{subscription_id}"
    path = f"{sub}/providers/Microsoft.Authorization/roleDefinitions/{role_definition_guid}"
    return _req(OP_ROLE_DEFINITIONS, sub, path, AUTHZ_API)


def role_definition_guid(role_definition_id: str) -> str:
    guid = role_definition_id.rstrip("/").rsplit("/", 1)[-1].lower()
    if not GUID_RE.fullmatch(guid):
        raise ParseError(f"role definition id does not end in a GUID: {role_definition_id!r}")
    return guid


def deny_assignments_request(subscription_id: str) -> ApiRequest:
    sub = f"/subscriptions/{subscription_id}"
    return _req(
        OP_DENY_ASSIGNMENTS,
        sub,
        f"{sub}/providers/Microsoft.Authorization/denyAssignments",
        AUTHZ_API,
    )


def role_eligibility_request(subscription_id: str) -> ApiRequest:
    """Eligibility schedules at, above and below the subscription (no ``$filter``)."""
    sub = f"/subscriptions/{subscription_id}"
    return _req(
        OP_ROLE_ELIGIBILITY,
        sub,
        f"{sub}/providers/Microsoft.Authorization/roleEligibilitySchedules",
        PIM_API,
    )


def resources_request(resource_group_id: str) -> ApiRequest:
    return _req(OP_RG_RESOURCES, resource_group_id, f"{resource_group_id}/resources", RESOURCES_API)


def resource_settings_request(resource_id: str, resource_type: str) -> ApiRequest:
    """GET one Key Vault or storage account (``resource_type`` lowercased ARM type)."""
    op = SETTINGS_TYPES[resource_type]
    api = KEY_VAULT_API if op == OP_KEY_VAULT else STORAGE_API
    return _req(op, resource_id, resource_id, api)


# --- parsers ----------------------------------------------------------------------------


def _props(item: dict[str, Any]) -> dict[str, Any]:
    props = item.get("properties")
    if not isinstance(props, dict):
        raise ParseError("ARM item without properties")
    return props


def _str(d: dict[str, Any], key: str) -> str:
    value = d.get(key)
    if not isinstance(value, str) or not value:
        raise ParseError(f"missing string field {key!r}")
    return value


def scope_entity(b: SnapshotBuilder, scope_id: str, priority: int = PRIORITY_STUB) -> str:
    """Register an ARM scope/resource entity for an assignment scope."""
    if scope_id == TENANT_ROOT_SCOPE:
        return b.entity(scope_id, "scope", display_name="Root scope (/)", priority=priority)
    level = parse_arm_id(scope_id).level
    etype: EntityType = "resource" if level == "resource" else "scope"
    return b.entity(scope_id, etype, priority=priority)


def principal_stub(b: SnapshotBuilder, principal_id: str, principal_type: str) -> str | None:
    etype = PRINCIPAL_TYPES.get(principal_type)
    if etype is None:
        return None
    return b.entity(principal_id, etype, priority=PRIORITY_STUB)


def parse_role_assignments(
    b: SnapshotBuilder, items: list[dict[str, Any]], prov: Provenance
) -> tuple[set[str], list[str]]:
    """Add hasRbacRole edges. Returns (referenced role definition IDs, error codes)."""
    role_defs: set[str] = set()
    errors: list[str] = []
    for item in items:
        try:
            p = _props(item)
            principal = principal_stub(b, _str(p, "principalId"), _str(p, "principalType"))
            if principal is None:
                errors.append("unknown-principal-type")
                continue
            scope = scope_entity(b, _str(p, "scope"))
            role_def = parse_arm_id(_str(p, "roleDefinitionId")).format()
            role_defs.add(role_def)
            b.edge(
                {
                    "type": "hasRbacRole",
                    "src": principal,
                    "dst": scope,
                    "role_definition_id": role_def,
                    "assignment_id": _str(item, "id"),
                    "condition": p.get("condition") or None,
                },
                prov,
            )
        except (ParseError, ArmIdError, ValueError):
            errors.append("bad-item")
    return role_defs, errors


def parse_role_definition(b: SnapshotBuilder, body: dict[str, Any], entity_id: str) -> None:
    """Register a definition under ``entity_id``, the ID assignments reference."""
    p = _props(body)
    perms = p.get("permissions") or []
    if not isinstance(perms, list):
        raise ParseError("permissions must be a list")

    def collect(key: str) -> tuple[str, ...]:
        return tuple(sorted({a for perm in perms for a in (perm.get(key) or [])}))

    if role_definition_guid(_str(body, "id")) != role_definition_guid(entity_id):
        raise ParseError("role definition response does not match the requested definition")
    b.entity(
        entity_id,
        "roleDefinition",
        display_name=p.get("roleName"),
        properties={
            "roleType": p.get("type"),
            "actions": collect("actions"),
            "notActions": collect("notActions"),
            "dataActions": collect("dataActions"),
            "notDataActions": collect("notDataActions"),
        },
    )


def parse_deny_assignments(
    b: SnapshotBuilder, items: list[dict[str, Any]], prov: Provenance
) -> list[str]:
    errors: list[str] = []
    for item in items:
        try:
            p = _props(item)
            scope = scope_entity(b, _str(p, "scope"))
            perms = p.get("permissions") or []

            def collect(key: str, perms: list[dict[str, Any]] = perms) -> list[str]:
                return sorted({a for perm in perms for a in (perm.get(key) or [])})

            excluded = sorted({_str(x, "id") for x in p.get("excludePrincipals") or []})
            for principal in p.get("principals") or []:
                pid = _str(principal, "id")
                if pid == EVERYONE_PRINCIPAL_ID:
                    src = b.entity(
                        pid,
                        "group",
                        display_name="Everyone (deny assignment)",
                        properties={"synthetic": True},
                        priority=PRIORITY_STUB,
                    )
                else:
                    stub = principal_stub(b, pid, str(principal.get("type", "")))
                    if stub is None:
                        errors.append("unknown-principal-type")
                        continue
                    src = stub
                b.edge(
                    {
                        "type": "denyAssignment",
                        "src": src,
                        "dst": scope,
                        "deny_assignment_id": _str(item, "id"),
                        "actions": collect("actions"),
                        "not_actions": collect("notActions"),
                        "data_actions": collect("dataActions"),
                        "not_data_actions": collect("notDataActions"),
                        "excluded_principal_ids": excluded,
                        "do_not_apply_to_child_scopes": bool(p.get("doNotApplyToChildScopes")),
                    },
                    prov,
                )
        except (ParseError, ArmIdError, ValueError):
            errors.append("bad-item")
    return errors


def parse_resources(
    b: SnapshotBuilder, resource_group_id: str, items: list[dict[str, Any]], prov: Provenance
) -> list[str]:
    errors: list[str] = []
    rg = b.entity(resource_group_id, "scope", priority=PRIORITY_PRIMARY)
    for item in items:
        try:
            rid = b.entity(
                _str(item, "id"),
                "resource",
                display_name=item.get("name"),
                properties={
                    "resourceType": _str(item, "type"),
                    "location": item.get("location"),
                },
                priority=PRIORITY_PRIMARY,
            )
            b.edge({"type": "contains", "src": rg, "dst": rid}, prov)
            identity = item.get("identity")
            if isinstance(identity, dict):
                principals = []
                if isinstance(identity.get("principalId"), str):
                    principals.append(identity["principalId"])
                for ua in (identity.get("userAssignedIdentities") or {}).values():
                    if isinstance(ua, dict) and isinstance(ua.get("principalId"), str):
                        principals.append(ua["principalId"])
                for mi in sorted(set(principals)):
                    mid = b.entity(mi, "managedIdentity", priority=PRIORITY_STUB)
                    b.edge({"type": "hasIdentity", "src": rid, "dst": mid}, prov)
        except (ParseError, ArmIdError, ValueError):
            errors.append("bad-item")
    return errors


def _optional_bool(p: dict[str, Any], key: str) -> bool | None:
    value = p.get(key)
    if value is None or isinstance(value, bool):
        return value
    raise ParseError(f"{key} must be a boolean")


def parse_key_vault(
    b: SnapshotBuilder, vault_id: str, body: dict[str, Any], tenant_id: str, prov: Provenance
) -> list[str]:
    """Permission model plus one hasAccessPolicy edge per access policy entry.

    Policies for another tenant's principals are skipped (``foreign-tenant-policy``).
    A policy principal that no Graph listing returns is dropped at build time and
    reported under ``edges`` in coverage.
    """
    if parse_arm_id(_str(body, "id")).format() != parse_arm_id(vault_id).format():
        raise ParseError("vault response does not match the requested vault")
    p = _props(body)
    b.annotate(vault_id, {"enableRbacAuthorization": _optional_bool(p, "enableRbacAuthorization")})
    errors: list[str] = []
    policies = p.get("accessPolicies") or []
    if not isinstance(policies, list):
        raise ParseError("accessPolicies must be a list")
    for policy in policies:
        try:
            if str(policy.get("tenantId", "")).lower() != tenant_id.lower():
                errors.append("foreign-tenant-policy")
                continue
            perms = policy.get("permissions") or {}

            def names(key: str, perms: dict[str, Any] = perms) -> list[str]:
                return [str(x) for x in perms.get(key) or []]

            b.edge(
                {
                    "type": "hasAccessPolicy",
                    "src": _str(policy, "objectId"),
                    "dst": vault_id,
                    "secrets": names("secrets"),
                    "keys": names("keys"),
                    "certificates": names("certificates"),
                },
                prov,
            )
        except (ParseError, ValueError, AttributeError):
            errors.append("bad-item")
    return errors


def parse_storage_account(b: SnapshotBuilder, account_id: str, body: dict[str, Any]) -> None:
    """``allowSharedKeyAccess``: null or absent means Azure's default (allowed)."""
    if parse_arm_id(_str(body, "id")).format() != parse_arm_id(account_id).format():
        raise ParseError("storage response does not match the requested account")
    p = _props(body)
    b.annotate(account_id, {"allowSharedKeyAccess": _optional_bool(p, "allowSharedKeyAccess")})


def parse_role_eligibility(
    b: SnapshotBuilder, items: list[dict[str, Any]], prov: Provenance
) -> tuple[int, list[str]]:
    """Add hasEligibleRole (arm) edges for principals already in the snapshot.

    Returns (rows skipped because the principal is not in the snapshot, errors). A
    principal the snapshot does not hold cannot be controlled by the assumed
    compromised identity, so its eligibility cannot add reach.
    """
    skipped = 0
    errors: list[str] = []
    for item in items:
        try:
            p = _props(item)
            principal = _str(p, "principalId").lower()
            if not b.has(principal):
                skipped += 1
                continue
            scope = scope_entity(b, _str(p, "scope"))
            b.edge(
                {
                    "type": "hasEligibleRole",
                    "src": principal,
                    "dst": scope,
                    "plane": "arm",
                    "role_definition_id": parse_arm_id(_str(p, "roleDefinitionId")).format(),
                    "schedule_id": item.get("id") if isinstance(item.get("id"), str) else None,
                },
                prov,
            )
        except (ParseError, ArmIdError, ValueError):
            errors.append("bad-item")
    return skipped, errors
