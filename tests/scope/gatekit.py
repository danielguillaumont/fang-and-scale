"""Shared builders for gate tests."""

from __future__ import annotations

from typing import Any

from fns.models.scope import ScopeManifest
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal
from tests.factories import NOW, RG, SP_AGENT, SUB, TENANT, scope_dict

ARM_READ = "arm:Microsoft.Authorization/roleAssignments/read"
ARM_READ2 = "arm:Microsoft.Authorization/roleDefinitions/read"
GRAPH_READ = "graph:GET /servicePrincipals"
ARM_WRITE = "arm:Microsoft.Authorization/roleAssignments/write"
LIST_KEYS = "arm:Microsoft.Storage/storageAccounts/listKeys/action"
GRAPH_WRITE = "graph:POST /servicePrincipals/{id}/addPassword"

ARM_HOST = "https://management.azure.com"
GRAPH_HOST = "https://graph.microsoft.com"
RA_PATH = "providers/Microsoft.Authorization/roleAssignments"
ARM_URL = f"{ARM_HOST}{RG}/{RA_PATH}?api-version=2022-04-01"
SUB_URL = f"{ARM_HOST}/subscriptions/{SUB}/{RA_PATH}?api-version=2022-04-01"
GRAPH_URL = f"{GRAPH_HOST}/v1.0/servicePrincipals"


def manifest(**overrides: Any) -> ScopeManifest:
    return ScopeManifest.model_validate(scope_dict(**overrides))


_DEFAULT: Any = object()


def make_gate(
    m: Any = _DEFAULT,
    *,
    signed_in: str = TENANT,
    clock: FrozenClock | None = None,
    journal: InMemoryJournal | None = None,
    principal: str | None = SP_AGENT,
) -> tuple[Gate, InMemoryJournal, FrozenClock]:
    """``principal`` is the signed-in principal (the token's oid); prove needs one."""
    clock = clock or FrozenClock(NOW)
    journal = journal or InMemoryJournal()
    gate = Gate(
        manifest() if m is _DEFAULT else m,
        signed_in_tenant=signed_in,
        journal=journal,
        clock=clock,
        run_id="run-test",
        signed_in_principal=principal,
    )
    return gate, journal, clock
