"""Test data builders. Placeholder GUIDs only (CLAUDE.md rule 6)."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any


def pid(n: int) -> str:
    """Placeholder GUID number n."""
    return f"00000000-0000-4000-8000-{n:012d}"


TENANT = pid(1)
OTHER_TENANT = pid(2)
SUB = pid(10)
SUB2 = pid(11)
RG = f"/subscriptions/{SUB}/resourceGroups/rg-fns-lab"
RG2 = f"/subscriptions/{SUB}/resourceGroups/rg-fns-other"
SP_AGENT = pid(100)
SP_VERIFIER = pid(101)
APP_TARGET = pid(102)
SP_GRAPH = pid(103)
KV = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-crown-jewels"
OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE = "b24988ac-6180-42a0-ab88-20f7382dd24c"
RA = "providers/Microsoft.Authorization/roleAssignments"
DA = "providers/Microsoft.Authorization/denyAssignments"

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 12, 2, 12, 0, tzinfo=UTC)

SCOUT_OPS = [
    "arm:Microsoft.Authorization/roleAssignments/read",
    "arm:Microsoft.Authorization/roleDefinitions/read",
    "graph:GET /servicePrincipals",
]


def scope_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "version": 1,
        "tenant_id": TENANT,
        "subscription_ids": [SUB],
        "allowed_resource_groups": [RG],
        "test_identities": [{"object_id": SP_AGENT, "kind": "servicePrincipal", "name": "agent"}],
        "allowed_operations": {"scout": list(SCOUT_OPS)},
        "budget": {"max_api_calls": 100, "max_minutes": 10},
        "expires_at": LATER.isoformat(),
    }
    base.update(overrides)
    return base


def contract_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "version": 1,
        "contract": "billing-agent-blast-radius",
        "assume_compromised": "sp:sp-billing-agent",
        "must_not_reach": [
            {"resource": "kv-crown-jewels", "operations": ["secrets/get", "secrets/list"]},
            {"directory": "tenant", "operations": ["roleAssignments/write"]},
        ],
        "must_still_do": [{"resource": "st-invoices", "operations": ["blob/read"]}],
    }
    base.update(overrides)
    return base


def _prov(op: str = "arm:Microsoft.Authorization/roleAssignments/read") -> dict[str, Any]:
    return {"source_api": op, "request_id": "req-1", "observed_at": NOW.isoformat()}


def snapshot_dict() -> dict[str, Any]:
    sub_id = f"/subscriptions/{SUB}"
    role_def = f"{sub_id}/providers/Microsoft.Authorization/roleDefinitions/{CONTRIBUTOR_ROLE}"
    return copy.deepcopy(
        {
            "version": 1,
            "mode": "FIXTURE",
            "tenant_id": TENANT,
            "collected_at": NOW.isoformat(),
            "collector_version": "0.0.1",
            "entities": [
                {"id": sub_id, "type": "scope", "display_name": "lab-sub"},
                {"id": RG, "type": "scope", "display_name": "rg-fns-lab"},
                {
                    "id": KV,
                    "type": "resource",
                    "display_name": "kv-crown-jewels",
                    "properties": {"kind": "Microsoft.KeyVault/vaults", "tags": ["lab", "fns"]},
                },
                {"id": role_def, "type": "roleDefinition", "display_name": "Contributor"},
                {
                    "id": SP_AGENT,
                    "type": "servicePrincipal",
                    "display_name": "sp-billing-agent",
                    "properties": {"appId": pid(200), "servicePrincipalType": "Application"},
                },
                {"id": APP_TARGET, "type": "application", "display_name": "app-escalation-target"},
                {"id": SP_GRAPH, "type": "servicePrincipal", "display_name": "Microsoft Graph"},
            ],
            "edges": [
                {"type": "contains", "src": sub_id, "dst": RG, "provenance": _prov()},
                {"type": "contains", "src": RG, "dst": KV, "provenance": _prov()},
                {
                    "type": "hasRbacRole",
                    "src": SP_AGENT,
                    "dst": RG,
                    "role_definition_id": role_def,
                    "assignment_id": f"{RG}/{RA}/{pid(300)}",
                    "provenance": _prov(),
                },
                {
                    "type": "owns",
                    "src": SP_AGENT,
                    "dst": APP_TARGET,
                    "provenance": _prov("graph:GET /applications/{id}/owners"),
                },
                {
                    "type": "hasAppRole",
                    "src": SP_AGENT,
                    "dst": SP_GRAPH,
                    "app_role_id": "18a4783c-866b-4cc7-a460-3d5e5662c884",
                    "app_role_value": "Application.ReadWrite.OwnedBy",
                    "provenance": _prov("graph:GET /servicePrincipals/{id}/appRoleAssignments"),
                },
                {
                    "type": "denyAssignment",
                    "src": SP_AGENT,
                    "dst": KV,
                    "deny_assignment_id": f"{KV}/{DA}/{pid(301)}",
                    "actions": ["*/write", "*/delete"],
                    "excluded_principal_ids": [SP_VERIFIER],
                    "provenance": _prov("arm:Microsoft.Authorization/denyAssignments/read"),
                },
            ],
            "coverage": {
                "collectors": [
                    {
                        "name": "arm.role-assignments",
                        "status": "complete",
                        "items": 1,
                        "duration_ms": 12,
                    },
                    {
                        "name": "graph.directory-roles",
                        "status": "partial",
                        "items": 0,
                        "error_codes": ["http-403"],
                        "duration_ms": 30,
                    },
                ],
                "not_collected": [
                    {"surface": "pim-eligibility", "reason": "not collected in M1"},
                ],
            },
        }
    )
