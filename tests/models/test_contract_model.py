from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from fns.models.contract import Contract, DirectoryTarget, ResourceTarget, load_contract
from tests.factories import contract_dict, pid

EXAMPLE = Path(__file__).resolve().parents[2] / "contracts" / "examples" / "billing-agent.fns.yaml"


def test_example_contract_loads() -> None:
    c = load_contract(EXAMPLE)
    assert c.contract == "billing-agent-blast-radius"
    assert c.version == 2
    assert {type(i).__name__ for i in c.must_not_reach} == {
        "ResourceTarget",
        "DirectoryTarget",
        "ApplicationTarget",
    }
    assert any(isinstance(i, DirectoryTarget) for i in c.must_not_reach)
    assert c.on_inconclusive == "fail"
    assert c.budget.max_inconclusive == 3  # approved 2026-11-27, three named items
    assert [a.item for a in c.budget.accepted_inconclusive] == [
        "directory:tenant applications/credentials/update",
        "directory:tenant roleAssignments/write",
        "resource:st-invoices blob/write",
    ]
    assert all(a.reason for a in c.budget.accepted_inconclusive)


def test_defaults() -> None:
    c = Contract.model_validate(contract_dict())
    assert c.must_still_do[0].source == "declared"
    assert c.budget.max_critical_reachable == 0
    assert c.budget.max_inconclusive == 0
    assert c.on_inconclusive == "fail"


def test_items_and_operations_sorted() -> None:
    c = Contract.model_validate(
        contract_dict(
            must_not_reach=[
                {"resource": "st-payroll", "operations": ["listKeys", "blob/read"]},
                {"directory": "tenant", "operations": ["roleAssignments/write"]},
                {"resource": "kv-crown-jewels", "operations": ["secrets/list", "secrets/get"]},
            ]
        )
    )
    assert [i.target_key for i in c.must_not_reach] == [
        "directory:tenant",
        "resource:kv-crown-jewels",
        "resource:st-payroll",
    ]
    assert c.must_not_reach[1].operations == ("secrets/get", "secrets/list")
    assert c.must_not_reach[2].operations == ("blob/read", "listKeys")


@pytest.mark.parametrize(
    "ref", ["sp:sp-billing-agent", f"sp:{pid(7)}", "mi:id-runner", f"objectId:{pid(8)}"]
)
def test_identity_refs(ref: str) -> None:
    assert Contract.model_validate(contract_dict(assume_compromised=ref)).assume_compromised == ref


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": 3},
        {"must_not_reach": [{"application": "id-verifier", "operations": ["owners/update"]}]},
        {"must_not_reach": [{"service_principal": "a b", "operations": ["owners/update"]}]},
        {"must_still_do": [{"application": "x", "operations": ["owners/update"]}]},
        {"contract": "Has Spaces"},
        {"contract": "UPPER"},
        {"assume_compromised": "billing-agent"},
        {"assume_compromised": "user:alice"},
        {"assume_compromised": "objectId:not-a-guid"},
        {"must_not_reach": []},
        # the old PLAN.md shorthand is no longer accepted
        {"must_not_reach": [{"directory": ["roleAssignments/write"]}]},
        {"must_not_reach": [{"directory": "other-tenant", "operations": ["x"]}]},
        {"must_not_reach": [{"resource": "kv", "operations": []}]},
        {"must_not_reach": [{"resource": "kv"}]},
        {"must_not_reach": [{"resource": "kv", "directory": "tenant", "operations": ["x"]}]},
        {"must_not_reach": [{"operations": ["x"]}]},
        {"must_not_reach": [{"resource": "kv", "operations": ["secrets/get", "Secrets/Get"]}]},
        {"must_not_reach": [{"resource": "kv", "operations": ["secrets get"]}]},
        {"must_not_reach": [{"resource": "kv", "operations": ["*"]}]},
        {"must_not_reach": [{"resource": "kv one", "operations": ["x"]}]},
        {
            "must_not_reach": [
                {"resource": "kv", "operations": ["a"]},
                {"resource": "KV", "operations": ["b"]},
            ]
        },
        {"must_still_do": [{"resource": "st", "operations": ["blob/read"], "source": "guessed"}]},
        {"must_still_do": [{"directory": "tenant", "operations": ["x"]}]},
        {"budget": {"max_critical_reachable": -1}},
        {"budget": {"max_inconclusive": -1}},
        {"budget": {"max_critical": 0}},
        {"on_inconclusive": "ignore"},
        {"unexpected": True},
    ],
)
def test_invalid_contracts(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(contract_dict(**overrides))


def test_same_target_and_operation_in_both_lists_rejected() -> None:
    with pytest.raises(ValidationError, match="both must_not_reach and must_still_do"):
        Contract.model_validate(
            contract_dict(
                must_not_reach=[{"resource": "st-invoices", "operations": ["blob/write"]}],
                must_still_do=[
                    {"resource": "ST-Invoices", "operations": ["blob/read", "Blob/Write"]}
                ],
            )
        )


def test_same_target_different_operations_is_fine() -> None:
    c = Contract.model_validate(
        contract_dict(
            must_not_reach=[{"resource": "st-invoices", "operations": ["listKeys"]}],
            must_still_do=[{"resource": "st-invoices", "operations": ["blob/read"]}],
        )
    )
    assert len(c.must_still_do) == 1


def test_full_arm_id_target_accepted() -> None:
    arm = f"/subscriptions/{pid(10)}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv"
    c = Contract.model_validate(
        contract_dict(must_not_reach=[{"resource": arm, "operations": ["secrets/get"]}])
    )
    assert isinstance(c.must_not_reach[0], ResourceTarget)


def test_contract_digest_stable_under_reordering() -> None:
    a = Contract.model_validate(contract_dict())
    d = contract_dict()
    d["must_not_reach"] = list(reversed(d["must_not_reach"]))
    b = Contract.model_validate(d)
    assert a.digest() == b.digest()
