"""Findings and evidence: the "never claim more than the evidence" rule in types.

Validation rules (docs/PLAN.md section 4):

- ``pass`` on a ``must_not_reach`` item needs rung ``observed`` evidence with
  outcome ``denied``, and no observed/logged success.
- ``pass`` on a ``must_still_do`` item needs ``observed`` or ``logged``
  evidence with outcome ``allowed``, and no observed/logged denial.
- ``fail`` needs at least one piece of evidence pointing the failing way
  (``allowed`` for must_not_reach, ``denied`` for must_still_do), at any rung.
- Coverage must match the highest rung that produced a result
  (``allowed``/``denied``): observed/logged -> verified, evaluated ->
  evaluated-only, modeled -> modeled-only. With no result, coverage is
  ``not-assessed`` or ``out-of-scope`` and the verdict must be ``inconclusive``.
- Gap labels need the disagreement they name.
"""

from __future__ import annotations

import hashlib
from typing import Any, ClassVar, Final, Literal

from pydantic import Field, field_validator, model_validator

from fns.models.base import FnsModel
from fns.models.ids import TzDatetime

Rung = Literal["modeled", "evaluated", "observed", "logged"]
RUNG_ORDER: Final[dict[str, int]] = {"modeled": 1, "evaluated": 2, "observed": 3, "logged": 4}
Outcome = Literal["allowed", "denied", "unknown", "not-run"]
CoverageState = Literal[
    "verified", "evaluated-only", "modeled-only", "not-assessed", "out-of-scope"
]
Verdict = Literal["pass", "fail", "inconclusive"]
Gap = Literal["model-gap", "platform-gap", "detection-gap"]
ItemKind = Literal["must_not_reach", "must_still_do"]

_RESULT_OUTCOMES: Final = frozenset({"allowed", "denied"})
_COVERAGE_BY_RUNG: Final[dict[str, str]] = {
    "modeled": "modeled-only",
    "evaluated": "evaluated-only",
    "observed": "verified",
    "logged": "verified",
}


class Evidence(FnsModel):
    __volatile__: ClassVar[frozenset[str]] = frozenset({"observed_at"})

    rung: Rung
    outcome: Outcome
    source: str = Field(min_length=1, max_length=512)
    """What produced it: a scope operation, probe name, or log query name."""
    artifact_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    """sha256 of the stored request/response artifact."""
    observed_at: TzDatetime | None = None
    notes: str | None = None
    path_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    """The escalation path this evidence rests on, in the enclosing ContainReport."""

    def sort_key(self) -> tuple[int, str, str, str]:
        return (RUNG_ORDER[self.rung], self.outcome, self.source, self.artifact_digest or "")


def finding_id(contract: str, item_kind: str, target: str, operation: str) -> str:
    text = "\x1f".join((contract, item_kind, target.lower(), operation.lower()))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Finding(FnsModel):
    id: str = Field(pattern=r"^[0-9a-f]{64}$")
    """sha256 of (contract, item_kind, target, operation); computed if omitted."""
    contract: str = Field(min_length=1)
    item_kind: ItemKind
    target: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    verdict: Verdict
    coverage: CoverageState
    evidence: tuple[Evidence, ...] = ()
    reasons: tuple[str, ...] = Field(min_length=1)
    """Human-readable explanation; at least one, in the order they apply."""
    gap: Gap | None = None

    @model_validator(mode="before")
    @classmethod
    def _fill_id(cls, data: Any) -> Any:
        if isinstance(data, dict) and "id" not in data:
            parts = [data.get(k) for k in ("contract", "item_kind", "target", "operation")]
            if all(isinstance(p, str) for p in parts):
                return {**data, "id": finding_id(*parts)}  # type: ignore[arg-type]
        return data

    @field_validator("evidence")
    @classmethod
    def _sort_evidence(cls, v: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
        return tuple(sorted(v, key=Evidence.sort_key))

    @model_validator(mode="after")
    def _evidence_supports_claim(self) -> Finding:
        expected_id = finding_id(self.contract, self.item_kind, self.target, self.operation)
        if self.id != expected_id:
            raise ValueError("finding id does not match its contract/item/target/operation")

        ev = self.evidence

        def has(rungs: set[str], outcome: str) -> bool:
            return any(e.rung in rungs and e.outcome == outcome for e in ev)

        # Verdict must be backed by evidence.
        if self.verdict == "pass":
            if self.item_kind == "must_not_reach":
                if not has({"observed"}, "denied"):
                    raise ValueError("pass on must_not_reach requires an observed denial (rung 3)")
                if has({"observed", "logged"}, "allowed"):
                    raise ValueError("pass on must_not_reach contradicted by an observed success")
            else:
                if not has({"observed", "logged"}, "allowed"):
                    raise ValueError("pass on must_still_do requires observed or logged success")
                if has({"observed", "logged"}, "denied"):
                    raise ValueError("pass on must_still_do contradicted by an observed denial")
        if self.verdict == "fail":
            failing = "allowed" if self.item_kind == "must_not_reach" else "denied"
            if not has(set(RUNG_ORDER), failing):
                raise ValueError(
                    f"fail on {self.item_kind} requires evidence with outcome {failing}"
                )

        # Coverage must match the strongest rung that produced a result.
        results = [e for e in ev if e.outcome in _RESULT_OUTCOMES]
        if results:
            top = max(results, key=lambda e: RUNG_ORDER[e.rung]).rung
            if self.coverage != _COVERAGE_BY_RUNG[top]:
                raise ValueError(f"coverage {self.coverage} does not match highest rung {top}")
        else:
            if self.coverage not in {"not-assessed", "out-of-scope"}:
                raise ValueError(
                    f"coverage {self.coverage} claimed without any allowed/denied evidence"
                )
            if self.verdict != "inconclusive":
                raise ValueError("a finding without results must be inconclusive")

        # Gap labels need the disagreement they name.
        if self.gap == "model-gap" and not (
            has({"modeled"}, "allowed") and has({"observed"}, "denied")
        ):
            raise ValueError("model-gap requires modeled allowed and observed denied")
        if self.gap == "platform-gap" and not (
            has({"evaluated"}, "denied") and has({"observed"}, "allowed")
        ):
            raise ValueError("platform-gap requires evaluated denied and observed allowed")
        if self.gap == "detection-gap" and not (
            has({"observed"}, "allowed") and not any(e.rung == "logged" for e in ev)
        ):
            raise ValueError("detection-gap requires an observed success with no logged evidence")
        return self
