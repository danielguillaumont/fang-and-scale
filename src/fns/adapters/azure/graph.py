"""Microsoft Graph request catalogue and pure response parsers.

Every list uses ``$select`` so only the fields we model are fetched: less data
exposure and fewer volatile fields between runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from fns.adapters.azure.http import GRAPH_BASE, ApiRequest
from fns.inventory.builder import (
    PRIORITY_PRIMARY,
    PRIORITY_REFERENCE,
    PRIORITY_STUB,
    SnapshotBuilder,
)
from fns.models.armid import GUID_RE
from fns.models.snapshot import AGENT_ID_ODATA_TYPES, AGENT_ID_PROPERTY, EntityType, Provenance
from fns.scope.targets import DirectoryTarget

OP_SERVICE_PRINCIPALS: Final = "graph:GET /servicePrincipals"
OP_APPLICATIONS: Final = "graph:GET /applications"
OP_SP_OWNERS: Final = "graph:GET /servicePrincipals/{id}/owners"
OP_APP_OWNERS: Final = "graph:GET /applications/{id}/owners"
OP_SP_APP_ROLE_ASSIGNMENTS: Final = "graph:GET /servicePrincipals/{id}/appRoleAssignments"
OP_SP_MEMBER_OF: Final = "graph:GET /servicePrincipals/{id}/memberOf"
OP_DIR_ROLE_DEFINITIONS: Final = "graph:GET /roleManagement/directory/roleDefinitions"
OP_DIR_ROLE_ASSIGNMENTS: Final = "graph:GET /roleManagement/directory/roleAssignments"

OP_DIR_ROLE_ELIGIBILITY: Final = "graph:GET /roleManagement/directory/roleEligibilitySchedules"
OP_SUBSCRIBED_SKUS: Final = "graph:GET /subscribedSkus"
PIM_OPERATIONS: Final = (OP_DIR_ROLE_ELIGIBILITY, OP_SUBSCRIBED_SKUS)
"""Entra PIM eligibility and the licences that show whether PIM exists (M3 E1)."""

OP_APPLICATION: Final = "graph:GET /applications/{id}"
OP_SERVICE_PRINCIPAL: Final = "graph:GET /servicePrincipals/{id}"
CREDENTIAL_OPERATIONS: Final = (OP_APPLICATION, OP_SERVICE_PRINCIPAL)
"""Per-object reads for key and password credential metadata (2026-11-28, pending review).

Optional, like PIM: the collector runs only for the ones a scope lists, so scopes
and recordings made before they existed replay unchanged. Application.Read.All
(already granted to the scout) is the least-privileged application permission for
both (Microsoft Learn, "Get application" and "Get servicePrincipal", read
2026-11-28). The lab scope does not list them yet."""
CREDENTIAL_SELECT: Final = "id,keyCredentials,passwordCredentials"
"""A list never returns ``keyCredentials`` (only a single-object read with ``$select``
does), and that read also returns ``key``, the public certificate data. The parser
keeps metadata only; :mod:`fns.fixtures.sanitize` redacts ``key``,
``customKeyIdentifier`` and ``hint`` in recordings."""
CREDENTIAL_KEY_FIELDS: Final = (
    "keyId",
    "displayName",
    "type",
    "usage",
    "startDateTime",
    "endDateTime",
)
CREDENTIAL_PASSWORD_FIELDS: Final = ("keyId", "displayName", "startDateTime", "endDateTime")
"""The only fields of ``keyCredential`` / ``passwordCredential`` the parser reads."""

PIM_PLAN_IDS: Final = frozenset({"eec0eb4f-6444-4f95-aba0-50c24d67f998"})
"""Service plans known to carry PIM: AAD_PREMIUM_P2 (Microsoft Entra ID P2).

Only used to name the plan in the reason. Any plan that is not in
:data:`PIM_FREE_PLAN_IDS` already keeps PIM open, whether or not it is listed here.
"""
PIM_FREE_PLAN_IDS: Final[frozenset[str]] = frozenset()
"""Service plan IDs known **not** to carry PIM, matched by ``servicePlanId`` only.

PIM is ``not-applicable`` only if every service plan of every live SKU is in this
set (2026-11-26 decision). A plan or SKU that is not, including one without an ID,
keeps ``pim-eligibility`` not collected, so findings stay inconclusive. Names are
never matched: SKU and plan names change and are not unique.

Empty on purpose. Add an ID only with its plan name and a source (Microsoft's
"Product names and service plan identifiers for licensing" list) and the date
checked. Until then only a tenant with no service plans at all, like the lab
(Entra ID Free, 0 SKUs), can be ``not-applicable``.
"""


@dataclass(frozen=True, slots=True)
class Licences:
    """What ``/subscribedSkus`` says about PIM, by service plan ID."""

    skus: tuple[str, ...]
    """SKU part numbers that are not ``Deleted``."""
    pim: tuple[str, ...]
    """``SKU/plan`` for plans known to carry PIM."""
    unknown: tuple[str, ...]
    """``SKU/plan`` for plans not known to be PIM-free (or a SKU with no plans)."""

    @property
    def rules_out_pim(self) -> bool:
        return not self.pim and not self.unknown


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
    **{odata: base for odata, (_kind, base) in AGENT_ID_ODATA_TYPES.items()},
}


def _agent_id_props(item: dict[str, Any], base: EntityType) -> dict[str, str]:
    """``{agentIdType: kind}`` for an Agent ID object of this base type, else ``{}``.

    Set only on Agent ID objects, so every other entity (and every existing
    snapshot digest) stays exactly as it was."""
    found = AGENT_ID_ODATA_TYPES.get(str(item.get("@odata.type", "")))
    if found is None or found[1] != base:
        return {}
    return {AGENT_ID_PROPERTY: found[0]}


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


def application_credentials_request(app_id: str) -> ApiRequest:
    return _req(OP_APPLICATION, f"/applications/{_guid(app_id)}?$select={CREDENTIAL_SELECT}")


def sp_credentials_request(sp_id: str) -> ApiRequest:
    return _req(
        OP_SERVICE_PRINCIPAL, f"/servicePrincipals/{_guid(sp_id)}?$select={CREDENTIAL_SELECT}"
    )


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


def directory_role_eligibility_request() -> ApiRequest:
    return _req(
        OP_DIR_ROLE_ELIGIBILITY,
        "/roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,"
        "roleDefinitionId,directoryScopeId",
    )


def subscribed_skus_request() -> ApiRequest:
    return _req(
        OP_SUBSCRIBED_SKUS,
        "/subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,servicePlans",
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
            agent = _agent_id_props(item, "servicePrincipal")
            etype: EntityType = (
                "managedIdentity" if kind == "ManagedIdentity" and not agent else "servicePrincipal"
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
                    **agent,
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
                properties={"appId": item.get("appId"), **_agent_id_props(item, "application")},
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
        properties=_agent_id_props(item, etype),
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


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def parse_credentials(
    b: SnapshotBuilder, owner: str, body: dict[str, Any], prov: Provenance
) -> tuple[int, list[str]]:
    """Add key/password credential **metadata** of one object. Returns (count, errors).

    Reads only :data:`CREDENTIAL_KEY_FIELDS` and :data:`CREDENTIAL_PASSWORD_FIELDS`:
    ``key``, ``customKeyIdentifier``, ``hint`` and ``secretText`` are never read, so
    no value can reach the snapshot whatever the response holds.
    """
    if _guid(body.get("id")) != _guid(owner):
        raise ParseError("credential response is for another object")
    count = 0
    errors: list[str] = []
    for kind, prop, fields in (
        ("key", "keyCredentials", CREDENTIAL_KEY_FIELDS),
        ("password", "passwordCredentials", CREDENTIAL_PASSWORD_FIELDS),
    ):
        rows = body.get(prop)
        if rows is None:
            errors.append(f"no-{prop}")
            continue
        if not isinstance(rows, list):
            raise ParseError(f"{prop} must be a list")
        for row in rows:
            if not isinstance(row, dict):
                errors.append("bad-item")
                continue
            meta = {f: row.get(f) for f in fields}
            try:
                b.credential(
                    {
                        "owner": owner,
                        "kind": kind,
                        "key_id": _guid(meta["keyId"]),
                        "display_name": _opt_str(meta["displayName"]),
                        "key_type": _opt_str(meta.get("type")),
                        "usage": _opt_str(meta.get("usage")),
                        "start": _opt_str(meta["startDateTime"]),
                        "end": _opt_str(meta["endDateTime"]),
                    },
                    prov,
                )
                count += 1
            except (ParseError, ValueError):
                errors.append("bad-item")
    return count, errors


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


def parse_directory_role_eligibility(
    b: SnapshotBuilder, items: list[dict[str, Any]], prov: Provenance
) -> tuple[int, list[str]]:
    """Add hasEligibleRole (directory) edges for principals already in the snapshot.

    Returns (rows skipped because the principal is not in the snapshot, errors).
    """
    skipped = 0
    errors: list[str] = []
    for item in items:
        try:
            principal = _guid(item.get("principalId"))
            if not b.has(principal):
                skipped += 1
                continue
            role = _guid(item.get("roleDefinitionId"))
            if not b.has(role):
                b.entity(role, "directoryRole", priority=PRIORITY_STUB)
            b.edge(
                {
                    "type": "hasEligibleRole",
                    "src": principal,
                    "dst": role,
                    "plane": "directory",
                    "role_definition_id": role,
                    "directory_scope_id": str(item.get("directoryScopeId") or "/"),
                    "schedule_id": item.get("id") if isinstance(item.get("id"), str) else None,
                },
                prov,
            )
        except ParseError:
            errors.append("bad-item")
    return skipped, errors


def pim_licences(
    items: list[dict[str, Any]], *, pim_free: frozenset[str] | None = None
) -> Licences:
    """Classify ``/subscribedSkus`` by service plan ID (never by name).

    A SKU whose capabilityStatus is ``Deleted`` is skipped: its licence is gone.
    Every other SKU counts with **all** its plans, whatever their
    provisioningStatus: skipping a disabled plan would make ``not-applicable``
    easier to reach, which is the wrong direction. A SKU with no plans, or a plan
    with no ID, is unknown.
    """
    free = PIM_FREE_PLAN_IDS if pim_free is None else pim_free
    skus: set[str] = set()
    pim: set[str] = set()
    unknown: set[str] = set()
    for sku in items:
        part = str(sku.get("skuPartNumber") or sku.get("skuId") or "unknown-sku")
        if str(sku.get("capabilityStatus") or "") == "Deleted":
            continue
        skus.add(part)
        plans = sku.get("servicePlans")
        if not isinstance(plans, list):
            raise ParseError("servicePlans must be a list")
        if not plans:
            unknown.add(f"{part}/(no service plans)")
        for plan in plans:
            if not isinstance(plan, dict):
                raise ParseError("each service plan must be an object")
            name = str(plan.get("servicePlanName") or "")
            plan_id = str(plan.get("servicePlanId") or "").lower()
            label = f"{part}/{name or plan_id or '(no id)'}"
            if plan_id in PIM_PLAN_IDS:
                pim.add(label)
            elif not GUID_RE.fullmatch(plan_id) or plan_id not in free:
                unknown.add(label)
    return Licences(tuple(sorted(skus)), tuple(sorted(pim)), tuple(sorted(unknown)))
