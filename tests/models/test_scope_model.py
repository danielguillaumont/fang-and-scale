from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from fns.models.scope import ScopeExpiredError, ScopeManifest, load_scope
from fns.yamlio import YamlError
from tests.factories import LATER, NOW, RG, RG2, SUB, SUB2, TENANT, pid, scope_dict


def _write(tmp_path: Path, data: dict[str, Any]) -> Path:
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return p


def test_valid_manifest() -> None:
    m = ScopeManifest.model_validate(scope_dict())
    assert str(m.tenant_id) == TENANT
    assert m.allowed_resource_groups == (RG.lower(),)
    assert "scout" in m.allowed_operations


def test_empty_lists_are_valid_and_allow_nothing() -> None:
    m = ScopeManifest.model_validate(
        scope_dict(
            subscription_ids=[],
            allowed_resource_groups=[],
            test_identities=[],
            allowed_operations={},
        )
    )
    assert m.subscription_ids == ()
    assert m.allowed_operations == {}


def test_lists_are_sorted_for_determinism() -> None:
    m = ScopeManifest.model_validate(
        scope_dict(subscription_ids=[SUB2, SUB], allowed_resource_groups=[RG2, RG])
    )
    assert [str(s) for s in m.subscription_ids] == [SUB, SUB2]
    assert m.allowed_resource_groups == tuple(sorted([RG.lower(), RG2.lower()]))


@pytest.mark.parametrize(
    "overrides",
    [
        {"tenant_idd": TENANT},  # typo / unknown field
        {"version": 2},
        {"tenant_id": "not-a-guid"},
        {"expires_at": "2026-12-01T00:00:00"},  # naive
        {"budget": {"max_api_calls": 0, "max_minutes": 1}},
        {"budget": {"max_api_calls": 1}},
        {"subscription_ids": [SUB, SUB]},
        {"allowed_resource_groups": [RG, RG]},
        {"allowed_resource_groups": [f"/subscriptions/{SUB}"]},  # not an RG
        {"allowed_resource_groups": [f"{RG}/providers/Microsoft.KeyVault/vaults/kv"]},
        {"allowed_resource_groups": ["rg-fns-lab"]},  # must be a full ID
        {"allowed_resource_groups": [f"/subscriptions/{SUB2}/resourceGroups/rg"]},  # sub not listed
        {"allowed_operations": {"deploy": ["graph:GET /servicePrincipals"]}},  # unknown verb
        {"allowed_operations": {"scout": ["arm:Microsoft.Authorization/roleAssignments/write"]}},
        {
            "allowed_operations": {
                "prove": ["arm:Microsoft.Storage/storageAccounts/listKeys/action"]
            }
        },
        {"allowed_operations": {"contain": ["graph:POST /servicePrincipals/{id}/addPassword"]}},
        {"allowed_operations": {"molt": ["graph:DELETE /applications/{id}"]}},
        {"allowed_operations": {"scout": ["arm:*/read"]}},
        {"allowed_operations": {"scout": ["graph:GET /a", "graph:GET /A"]}},  # dup by key
        {"test_identities": [{"object_id": pid(5), "kind": "user", "name": "x"}]},
        {
            "test_identities": [
                {"object_id": pid(5), "kind": "servicePrincipal", "name": "a"},
                {"object_id": pid(5), "kind": "servicePrincipal", "name": "b"},
            ]
        },
    ],
)
def test_invalid_manifests_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ScopeManifest.model_validate(scope_dict(**overrides))


@pytest.mark.parametrize("field", ["tenant_id", "budget", "expires_at", "version"])
def test_required_fields(field: str) -> None:
    data = scope_dict()
    del data[field]
    with pytest.raises(ValidationError):
        ScopeManifest.model_validate(data)


def test_strike_may_list_only_the_write_forms() -> None:
    # M4: a strike write must be one of the forms the write gate knows.
    m = ScopeManifest.model_validate(
        scope_dict(
            allowed_operations={"strike": ["arm:Microsoft.Storage/storageAccounts/listKeys/action"]}
        )
    )
    assert m.allowed_operations["strike"]
    with pytest.raises(ValidationError, match="only the M4 write forms"):
        ScopeManifest.model_validate(
            scope_dict(
                allowed_operations={"strike": ["arm:Microsoft.Authorization/roleAssignments/write"]}
            )
        )


def test_manifest_is_frozen() -> None:
    m = ScopeManifest.model_validate(scope_dict())
    with pytest.raises(ValidationError):
        m.tenant_id = m.tenant_id  # type: ignore[misc]


def test_load_scope_valid(tmp_path: Path) -> None:
    m = load_scope(_write(tmp_path, scope_dict()), now=NOW)
    assert str(m.tenant_id) == TENANT


def test_load_scope_expired(tmp_path: Path) -> None:
    path = _write(tmp_path, scope_dict())
    with pytest.raises(ScopeExpiredError):
        load_scope(path, now=LATER + timedelta(seconds=1))


def test_load_scope_expired_exactly_at_expiry(tmp_path: Path) -> None:
    with pytest.raises(ScopeExpiredError):
        load_scope(_write(tmp_path, scope_dict()), now=LATER)


def test_load_scope_duplicate_key(tmp_path: Path) -> None:
    p = tmp_path / "scope.yaml"
    p.write_text(
        yaml.safe_dump(scope_dict(), sort_keys=False) + f"tenant_id: {pid(9)}\n", encoding="utf-8"
    )
    with pytest.raises(YamlError, match="duplicate key"):
        load_scope(p, now=NOW)
