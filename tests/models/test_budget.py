"""``budget.accepted_inconclusive``: named inconclusive items, each with a reason.

Approved 2026-11-27 for the lab contract: ``max_inconclusive: 3``, naming invoices
``blob/write``, ``directory:tenant applications/credentials/update`` and
``directory:tenant roleAssignments/write``. Any other inconclusive must still fail.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from fns.contain.evaluate import _summary
from fns.models.budget import AcceptedInconclusive, unaccepted_inconclusive
from fns.models.contract import Contract, load_contract
from fns.yamlio import load_yaml

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "contracts" / "examples" / "billing-agent.fns.yaml"
ACCEPTED = [
    "directory:tenant applications/credentials/update",
    "directory:tenant roleAssignments/write",
    "resource:st-invoices blob/write",
]


def example(**budget: Any) -> dict[str, Any]:
    data = copy.deepcopy(load_yaml(EXAMPLE))
    data["budget"].update(budget)
    return data


def test_the_example_names_the_three_approved_items_each_with_a_reason() -> None:
    c = load_contract(EXAMPLE)
    assert c.budget.max_inconclusive == 3 and c.on_inconclusive == "fail"
    assert [a.item for a in c.budget.accepted_inconclusive] == ACCEPTED
    reasons = {a.item: a.reason for a in c.budget.accepted_inconclusive}
    assert "rung 2" in reasons["resource:st-invoices blob/write"]
    assert "tenant-wide" in reasons["directory:tenant applications/credentials/update"]
    assert "SD3" in reasons["directory:tenant roleAssignments/write"]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"max_inconclusive": 2}, "more than max_inconclusive 2"),
        (
            {
                "accepted_inconclusive": [
                    {"target": "directory:tenant", "operation": "x/y", "reason": "r"}
                ]
            },
            "not in the contract",
        ),
        (
            {
                "accepted_inconclusive": [
                    {
                        "target": "directory:tenant",
                        "operation": "roleAssignments/write",
                        "reason": " ",
                    }
                ]
            },
            "reason",
        ),
        (
            {
                "accepted_inconclusive": [
                    {"target": "directory:tenant", "operation": "roleAssignments/write"}
                ]
            },
            "reason",
        ),
        (
            {
                "accepted_inconclusive": 2
                * [
                    {
                        "target": "directory:tenant",
                        "operation": "roleAssignments/write",
                        "reason": "r",
                    }
                ]
            },
            "listed once",
        ),
        (
            {
                "accepted_inconclusive": [
                    {"target": "resource:st-payroll", "operation": "blob/write", "reason": "r"}
                ]
            },
            "not in the contract",
        ),
    ],
)
def test_bad_accepted_lists_are_refused(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Contract.model_validate(example(**change))


def test_accepting_needs_on_inconclusive_fail() -> None:
    data = example()
    data["on_inconclusive"] = "warn"
    with pytest.raises(ValidationError, match="needs on_inconclusive: fail"):
        Contract.model_validate(data)


def test_targets_match_whatever_their_case() -> None:
    a = AcceptedInconclusive(target="resource:ST-Invoices", operation="blob/write", reason="r")
    assert a.target == "resource:st-invoices"
    assert unaccepted_inconclusive([("resource:st-invoices", "blob/write")], [a]) == ()


def test_a_budget_naming_nothing_keeps_the_count_rule_and_its_digest() -> None:
    data = example(max_inconclusive=2)
    del data["budget"]["accepted_inconclusive"]
    c = Contract.model_validate(data)
    assert "accepted_inconclusive" not in c.canonical_json()
    assert unaccepted_inconclusive([("directory:tenant", "anything")], ()) == ()


def test_unaccepted_lists_every_other_inconclusive_item_sorted() -> None:
    c = load_contract(EXAMPLE)
    found = [
        ("resource:st-payroll", "listKeys"),
        ("directory:tenant", "roleAssignments/write"),
        ("application:id-verifier", "owners/update"),
    ]
    assert unaccepted_inconclusive(found, c.budget.accepted_inconclusive) == (
        "application:id-verifier owners/update",
        "resource:st-payroll listKeys",
    )


class _F:
    def __init__(self, target: str, operation: str, verdict: str, kind: str) -> None:
        self.target, self.operation, self.verdict, self.item_kind = target, operation, verdict, kind


def _outcomes(inconclusive: list[str]) -> list[Any]:
    c = load_contract(EXAMPLE)
    out = []
    for kind, items in (("must_not_reach", c.must_not_reach), ("must_still_do", c.must_still_do)):
        for i in items:
            for op in i.operations:
                key = f"{i.target_key} {op}"
                f = _F(i.target_key, op, "inconclusive" if key in inconclusive else "pass", kind)
                out.append(type("O", (), {"finding": f})())
    return out


@pytest.mark.parametrize(
    ("inconclusive", "code", "unaccepted"),
    [
        (ACCEPTED, 0, ()),
        (ACCEPTED[:2], 0, ()),
        ([], 0, ()),
        ([*ACCEPTED[:2], "resource:st-payroll listKeys"], 3, ("resource:st-payroll listKeys",)),
        (
            [*ACCEPTED, "application:id-verifier owners/update"],
            3,
            ("application:id-verifier owners/update",),
        ),
    ],
)
def test_contain_applies_the_same_rule(
    inconclusive: list[str], code: int, unaccepted: tuple[str, ...]
) -> None:
    s = _summary(load_contract(EXAMPLE), _outcomes(inconclusive))
    assert (s.exit_code, s.unaccepted_inconclusive) == (code, unaccepted)
