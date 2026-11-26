"""Mutation report (M5): does the contract notice when someone weakens the defence?

Each mutant adds one dangerous grant (or removes one deny assignment) to the
baseline, which is usually the hardened state. A mutant is *killed* when the
contract gains a failing finding it did not have before. Everything is modeled
(rung 1); no mutant is ever applied to a tenant.
"""

from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import Field, NonNegativeInt, model_validator

from fns.models.base import FnsModel
from fns.models.ids import TzDatetime

Operator = Literal[
    "owner-at-rg",
    "listkeys",
    "graph-app-permission",
    "app-owner",
    "remove-deny-assignment",
]
OPERATORS: tuple[Operator, ...] = (
    "owner-at-rg",
    "listkeys",
    "graph-app-permission",
    "app-owner",
    "remove-deny-assignment",
)
Outcome = Literal["killed", "survived", "inconclusive"]
"""``inconclusive``: no new failure, but new findings the model cannot decide. Not a kill."""


class MutantResult(FnsModel):
    id: str = Field(min_length=1)
    operator: Operator
    description: str
    outcome: Outcome
    rung: Literal["modeled"] = "modeled"
    new_failures: tuple[str, ...] = ()
    """``<target> <operation>`` for each must_not_reach finding that newly fails."""
    new_inconclusive: tuple[str, ...] = ()
    new_reasons: tuple[str, ...] = ()
    """For a mutant that was not killed: finding reasons that appear only with it. The
    model saw the change but it gave no failing finding (for example ownership without
    the Graph permission to use it)."""
    terraform_file: str | None = None
    terraform_diff: str | None = None
    terraform_note: str | None = None
    """Why there is no Terraform for this mutant, when there is none."""

    @model_validator(mode="after")
    def _consistent(self) -> MutantResult:
        if (self.outcome == "killed") != bool(self.new_failures):
            raise ValueError("a mutant is killed exactly when it adds a failing finding")
        if (self.terraform_diff is None) == (self.terraform_note is None):
            raise ValueError("give a Terraform diff or a note saying why there is none")
        return self


class NotApplicable(FnsModel):
    operator: Operator
    reason: str


class OperatorScore(FnsModel):
    operator: Operator
    killed: NonNegativeInt
    total: NonNegativeInt


class MutationReport(FnsModel):
    __volatile__: ClassVar[frozenset[str]] = frozenset({"generated_at", "tool_version"})

    version: Literal[1]
    mode: Literal["LIVE", "FIXTURE"]
    contract: str
    contract_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    """The input snapshot, before any hardening."""
    hardened_with: tuple[str, ...] = ()
    """Terraform addresses removed (in the model) before mutating, from `fns harden`."""
    baseline_exit_code: int
    baseline_failures: NonNegativeInt
    """Failing findings before mutation. Above 0, a mutant can only add to them."""
    baseline_inconclusive: NonNegativeInt
    killed: NonNegativeInt
    total: NonNegativeInt
    by_operator: tuple[OperatorScore, ...]
    mutants: tuple[MutantResult, ...]
    not_applicable: tuple[NotApplicable, ...] = ()
    generated_at: TzDatetime
    tool_version: str

    @model_validator(mode="after")
    def _counts(self) -> MutationReport:
        if self.total != len(self.mutants):
            raise ValueError("total must equal the number of mutants")
        if self.killed != sum(m.outcome == "killed" for m in self.mutants):
            raise ValueError("killed must equal the number of killed mutants")
        return self

    @property
    def score(self) -> str:
        return f"{self.killed}/{self.total}"
