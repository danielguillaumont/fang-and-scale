"""Microsoft Graph request catalogue and pure response parsers.

Every list uses ``$select`` so only the fields we model are fetched: less data
exposure and fewer volatile fields between runs.
"""

from __future__ import annotations

from typing import Any, Final

from fns.adapters.azure.http import GRAPH_BASE, ApiRequest
from fns.inventory.builder import (
    PRIORITY_PRIMARY,
    PRIORITY_REFERENCE,
    PRIORITY_STUB,
    SnapshotBuilder,
)
from fns.models.armid import GUID_RE
from fns.models.snapshot import EntityType, Provenance
from fns.scope.targets import DirectoryTarget

OP_SERVICE_PRINCIPALS: Final = "graph:GET /servicePrincipals"
OP_APPLICATIONS: Final = "graph:GET /applications"
OP_SP_OWNERS: Final = "graph:GET /servicePrincipals/{id}/owners"
OP_APP_OWNERS: Final = "graph:GET /applications/{id}/owners"
OP_SP_APP_ROLE_ASSIGNMENTS: Final = "graph:GET /servicePrincipals/{id}/appRoleAssignments"
OP_SP_MEMBER_OF: Final = "graph:GET /servicePrincipals/{id}/memberOf"
OP_DIR_ROLE_DEFINITIONS: Final = "graph:GET /roleManagement/directory/roleDefinitions"
OP_DIR_ROLE_ASSIGNMENTS: Final = "graph:GET /roleManagement/directory/roleAssignments"

GRAPH_OPERATIONS: Final = (
    OP_SERVICE_PRINCIPALS,
    OP_APPLICATIONS,
    OP_SP_OWNERS,
    OP_APP_OWNERS,
    OP_SP_APP_ROLE_ASSIGNMENTS,
    OP_SP_MEMBER_OF,
    OP_DIR_ROLE_DEFINITIONS,
    OP_DIR_ROLE_ASSIGNMENTS,
)

ODATA_TYPES: Final[dict[str, EntityType]] = {
    "#microsoft.graph.user": "user",
    "#microsoft.graph.group": "group",
    "#microsoft.graph.servicePrincipal": "servicePrincipal",
    "#microsoft.graph.application": "application",
}

_DIR = DirectoryTarget()


class ParseError(ValueError):
    pass


def _req(op: str, path_and_query: str) -> ApiRequest:
    return ApiRequest(api="graph", operation=op, target=_DIR, url=f"{GRAPH_BASE}{path_and_query}")


def _guid(value: object) -> str:
    if not isinstance(value, str) or not GUID_RE.fullmatch(value):
        raise ParseError(f"expected a GUID, got {value!r}")
    return value.lower()


def service_principals_request() -> ApiRequest:
    return _req(
        OP_SERVICE_PRINCIPALS,
        "/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,"
        "appOwnerOrganizationId,appRoles",
    )


def applications_request() -> ApiRequest:
    return _req(OP_APPLICATIONS, "/applications?$select=id,appId,displayName")


def sp_owners_request(sp_id: str) -> ApiRequest:
    return _req(OP_SP_OWNERS, f"/servicePrincipals/{_guid(sp_id)}/owners?$select=id,displayName")


def app_owners_request(app_id: str) -> ApiRequest:
    return _req(OP_APP_OWNERS, f"/applications/{_guid(app_id)}/owners?$select=id,displayName")


def sp_app_role_assignments_request(sp_id: str) -> ApiRequest:
    return _req(OP_SP_APP_ROLE_ASSIGNMENTS, f"/servicePrincipals/{_guid(sp_id)}/appRoleAssignments")


def sp_member_of_request(sp_id: str) -> ApiRequest:
    return _req(
        OP_SP_MEMBER_OF, f"/servicePrincipals/{_guid(sp_id)}/memberOf?$select=id,displayName"
    )


def directory_role_definitions_request() -> ApiRequest:
    return _req(
        OP_DIR_ROLE_DEFINITIONS,
        "/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn",
    )


def directory_role_assignments_request() -> ApiRequest:
    return _req(
        OP_DIR_ROLE_ASSIGNMENTS,
        "/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,"
        "directoryScopeId",
    )


# --- parsers --------------------------------------------------------------------------


def parse_service_principals(
    b: SnapshotBuilder, items: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Add SP / managed identity entities. Returns ({sp_id: {app_role_id: value}}, errors)."""
    roles: dict[str, dict[str, str]] = {}
    errors: list[str] = []
    for item in items:
        try:
            sp_id = _guid(item.get("id"))
            kind = item.get("servicePrincipalType")
            etype: EntityType = (
                "managedIdentity" if kind == "ManagedIdentity" else "servicePrincipal"
            )
            app_roles = {
                _guid(r.get("id")): str(r.get("value"))
                for r in item.get("appRoles") or []
                if isinstance(r, dict) and r.get("value")
            }
            roles[sp_id] = app_roles
            owner_org = item.get("appOwnerOrganizationId")
            b.entity(
                sp_id,
                etype,
                display_name=item.get("displayName"),
                properties={
                    "appId": item.get("appId"),
                    "servicePrincipalType": kind,
                    "appOwnerOrganizationId": owner_org.lower()
                    if isinstance(owner_org, str)
                    else None,
                    "appRoles": tuple(f"{rid}={val}" for rid, val in app_roles.items()),
                },
                priority=PRIORITY_PRIMARY,
            )
        except ParseError:
            errors.append("bad-item")
    return roles, errors


def parse_applications(
    b: SnapshotBuilder, items: list[dict[str, Any]], sp_by_app_id: dict[str, str], prov: Provenance
) -> list[str]:
    errors: list[str] = []
    for item in items:
        try:
            app_obj = b.entity(
                _guid(item.get("id")),
                "application",
                display_name=item.get("displayName"),
                properties={"appId": item.get("appId")},
                priority=PRIORITY_PRIMARY,
            )
            app_id = str(item.get("appId", "")).lower()
            sp = sp_by_app_id.get(app_id)
            if sp is not None:
                b.edge({"type": "instanceOf", "src": sp, "dst": app_obj}, prov)
        except ParseError:
            errors.append("bad-item")
    return errors


def _directory_object(b: SnapshotBuilder, item: dict[str, Any]) -> str | None:
    etype = ODATA_TYPES.get(str(item.get("@odata.type", "")))
    if etype is None:
        return None
    return b.entity(
        _guid(item.get("id")),
        etype,
        display_name=item.get("displayName"),
        priority=PRIORITY_REFERENCE,
    )


def parse_owners(
    b: SnapshotBuilder, owned_id: str, items: list[dict[str, Any]], prov: Provenance
) -> list[str]:
    errors: list[str] = []
    for item in items:
        try:
            owner = _directory_object(b, item)
            if owner is None:
                errors.append("unknown-object-type")
                continue
            b.edge({"type": "owns", "src": owner, "dst": owned_id}, prov)
        except ParseError:
            errors.append("bad-item")
    return errors


def parse_member_of(
    b: SnapshotBuilder, member_id: str, items: list[dict[str, Any]], prov: Provenance
) -> list[str]:
    errors: list[str] = []
    for item in items:
        try:
            if item.get("@odata.type") != "#microsoft.graph.group":
                continue  # directory roles / AUs also appear in memberOf; roles come from RBAC API
            group = _directory_object(b, item)
            if group is not None:
                b.edge({"type": "memberOf", "src": member_id, "dst": group}, prov)
        except ParseError:
            errors.append("bad-item")
    return errors


def parse_app_role_assignments(
    b: SnapshotBuilder,
    items: list[dict[str, Any]],
    roles: dict[str, dict[str, str]],
    prov: Provenance,
) -> list[str]:
    errors: list[str] = []
    for item in items:
        try:
            principal = _guid(item.get("principalId"))
            resource = _guid(item.get("resourceId"))
            role_id = _guid(item.get("appRoleId"))
            if not b.has(resource):
                b.entity(
                    resource,
                    "servicePrincipal",
                    display_name=item.get("resourceDisplayName"),
                    priority=PRIORITY_STUB,
                )
            b.edge(
                {
                    "type": "hasAppRole",
                    "src": principal,
                    "dst": resource,
                    "app_role_id": role_id,
                    "app_role_value": roles.get(resource, {}).get(role_id),
                    "assignment_id": item.get("id"),
                },
                prov,
            )
        except ParseError:
            errors.append("bad-item")
    return errors


def parse_directory_role_definitions(b: SnapshotBuilder, items: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for item in items:
        try:
            b.entity(
                _guid(item.get("id")),
                "directoryRole",
                display_name=item.get("displayName"),
                properties={"isBuiltIn": bool(item.get("isBuiltIn"))},
                priority=PRIORITY_PRIMARY,
            )
        except ParseError:
            errors.append("bad-item")
    return errors


def parse_directory_role_assignments(
    b: SnapshotBuilder, items: list[dict[str, Any]], prov: Provenance
) -> list[str]:
    errors: list[str] = []
    for item in items:
        try:
            b.edge(
                {
                    "type": "hasDirectoryRole",
                    "src": _guid(item.get("principalId")),
                    "dst": _guid(item.get("roleDefinitionId")),
                    "directory_scope_id": str(item.get("directoryScopeId") or "/"),
                    "assignment_id": item.get("id"),
                },
                prov,
            )
        except ParseError:
            errors.append("bad-item")
    return errors
