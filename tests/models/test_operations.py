from __future__ import annotations

import pytest

from fns.models.operations import OperationError, parse_operation


@pytest.mark.parametrize(
    ("op", "api", "is_read"),
    [
        ("arm:Microsoft.Authorization/roleAssignments/read", "arm", True),
        ("arm:Microsoft.Authorization/roleAssignments/write", "arm", False),
        ("arm:Microsoft.Authorization/roleAssignments/delete", "arm", False),
        ("arm:Microsoft.Storage/storageAccounts/listKeys/action", "arm", False),
        ("arm:Microsoft.KeyVault/vaults/secrets/getSecret/action", "arm", False),
        ("arm:Microsoft.Resources/subscriptions/resourceGroups/read", "arm", True),
        ("graph:GET /servicePrincipals", "graph", True),
        ("graph:GET /servicePrincipals/{id}/owners", "graph", True),
        ("graph:GET /roleManagement/directory/roleAssignments", "graph", True),
        ("graph:POST /servicePrincipals/{id}/appRoleAssignments", "graph", False),
        ("graph:POST /identity/conditionalAccess/evaluate", "graph", False),
        ("graph:PATCH /applications/{id}", "graph", False),
        ("graph:DELETE /applications/{id}", "graph", False),
        ("graph:PUT /applications/{id}/logo", "graph", False),
    ],
)
def test_classification(op: str, api: str, is_read: bool) -> None:
    parsed = parse_operation(op)
    assert parsed.api == api
    assert parsed.is_read is is_read
    assert parsed.raw == op


def test_comparison_key_is_case_insensitive_for_paths() -> None:
    a = parse_operation("arm:Microsoft.Authorization/roleAssignments/read")
    b = parse_operation("arm:microsoft.authorization/ROLEASSIGNMENTS/READ")
    assert a.key == b.key
    g1 = parse_operation("graph:GET /servicePrincipals")
    g2 = parse_operation("graph:GET /serviceprincipals")
    assert g1.key == g2.key


@pytest.mark.parametrize(
    "op",
    [
        "",
        "arm:",
        "arm:Microsoft.Authorization/roleAssignments",  # no verb
        "arm:Microsoft.Authorization/roleAssignments/*",  # no wildcards
        "arm:*/read",
        "arm:NoNamespace/read",
        "arm:Microsoft.Authorization/roleAssignments/read ",
        "graph:get /servicePrincipals",  # method must be upper case
        "graph:GET servicePrincipals",
        "graph:GET /servicePrincipals?$top=1",  # no query strings
        "graph:GET /servicePrincipals/",
        "graph:GET /servicePrincipals/*",
        "graph:TRACE /me",
        "aws:s3:GetObject",
        "Microsoft.Authorization/roleAssignments/read",
    ],
)
def test_malformed_operations_rejected(op: str) -> None:
    with pytest.raises(OperationError):
        parse_operation(op)


def test_non_string_rejected() -> None:
    with pytest.raises(OperationError):
        parse_operation(None)
