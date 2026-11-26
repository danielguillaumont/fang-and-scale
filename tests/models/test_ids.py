from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import BaseModel, ValidationError

from fns.models.armid import ArmIdError, parse_arm_id
from fns.models.ids import ArmId, Guid, TzDatetime, utc_isoformat
from tests.factories import RG, SUB


class _G(BaseModel):
    g: Guid


class _A(BaseModel):
    a: ArmId


class _T(BaseModel):
    t: TzDatetime


@pytest.mark.parametrize(
    "value",
    ["00000000-0000-4000-8000-000000000001", "ABCDEF01-2345-4789-8ABC-DEF012345678"],
)
def test_guid_accepts_and_normalizes(value: str) -> None:
    m = _G(g=value)  # type: ignore[arg-type]
    assert m.model_dump(mode="json")["g"] == value.lower()
    assert m.g == uuid.UUID(value)


@pytest.mark.parametrize(
    "value",
    [
        "{00000000-0000-4000-8000-000000000001}",
        "urn:uuid:00000000-0000-4000-8000-000000000001",
        "00000000000040008000000000000001",
        "00000000-0000-4000-8000-00000000000",
        "not-a-guid",
        "",
        12345,
        None,
    ],
)
def test_guid_rejects_non_canonical_forms(value: object) -> None:
    with pytest.raises(ValidationError):
        _G(g=value)  # type: ignore[arg-type]


def test_arm_id_normalized_to_lowercase() -> None:
    mixed = f"/SUBSCRIPTIONS/{SUB.upper()}/resourceGroups/RG-FNS-Lab"
    assert _A(a=mixed).a == RG.lower()


@pytest.mark.parametrize(
    ("value", "level"),
    [
        (f"/subscriptions/{SUB}", "subscription"),
        (RG, "resourceGroup"),
        (f"{RG}/providers/Microsoft.KeyVault/vaults/kv1", "resource"),
        (
            f"{RG}/providers/Microsoft.Storage/storageAccounts/st/blobServices/default/containers/$web",
            "resource",
        ),
        (
            f"{RG}/providers/Microsoft.KeyVault/vaults/kv1/providers/Microsoft.Authorization/"
            "roleAssignments/r1",
            "resource",
        ),
        (f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/r1", "resource"),
        ("/providers/Microsoft.Management/managementGroups/mg1", "managementGroup"),
        ("/providers/Microsoft.Authorization/roleDefinitions/r1", "tenant"),
    ],
)
def test_arm_id_levels(value: str, level: str) -> None:
    assert parse_arm_id(value).level == level
    assert parse_arm_id(parse_arm_id(value).format()) == parse_arm_id(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/",
        f"{RG}/",
        f"/subscriptions/{SUB}//resourceGroups/rg",
        f"/subscriptions/{SUB}/resourceGroups/../rg",
        f"/subscriptions/{SUB}/resourceGroups/./rg",
        f"/subscriptions/{SUB}/resourceGroups/rg%2Fother",
        f"/subscriptions/{SUB}/resourceGroups/rg lab",
        f"/subscriptions/{SUB}/resourceGroups/rg-l{chr(0x430)}b",  # Cyrillic a homoglyph
        f"/subscriptions/{SUB}/resourceGroups",
        "/subscriptions/not-a-guid/resourceGroups/rg",
        f"subscriptions/{SUB}",
        f"/tenants/{SUB}",
        f"{RG}/providers/NoDotNamespace/vaults/kv",
        f"{RG}/providers/Microsoft.KeyVault/vaults",
        f"{RG}/providers/Microsoft.KeyVault",
        f"{RG}/extra/segment",
        "/providers/Microsoft.Management/managementGroups",
        "/providers",
    ],
)
def test_arm_id_rejects_malformed(value: str) -> None:
    with pytest.raises(ArmIdError):
        parse_arm_id(value)


def test_arm_id_rejects_non_string() -> None:
    with pytest.raises(ArmIdError):
        parse_arm_id(42)


def test_resource_group_id_of_nested_resource() -> None:
    p = parse_arm_id(f"{RG}/providers/Microsoft.KeyVault/vaults/kv1")
    assert p.resource_group_id == RG.lower()


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValidationError):
        _T(t=datetime(2026, 1, 1))  # noqa: DTZ001
    with pytest.raises(ValidationError):
        _T(t="2026-01-01T00:00:00")  # type: ignore[arg-type]


def test_aware_datetime_normalized_to_utc() -> None:
    plus2 = timezone(timedelta(hours=2))
    t = _T(t=datetime(2026, 1, 1, 2, 0, tzinfo=plus2)).t
    assert t == datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    assert t.utcoffset() == timedelta(0)
    assert utc_isoformat(t) == "2026-01-01T00:00:00Z"
