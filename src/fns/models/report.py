"""``fns contain`` report: findings, the paths behind them, and the verdict.

The report digest excludes ``generated_at`` and ``tool_version`` so the same
snapshot and contract always give the same digest. ``mode`` is carried over
from the snapshot: a report built from a FIXTURE snapshot is a FIXTURE report.
"""

from __future__ import annotations

import hashlib
from typing import ClassVar, Literal

from pydantic import Field, NonNegativeInt, field_validator, model_validator

from fns.models.base import FnsModel
from fns.models.evidence import Finding, Rung
from fns.models.ids import TzDatetime

Digest = str


def path_id(finding_id: str, step_texts: tuple[str, ...]) -> str:
    text = "\x1f".join((finding_id, *step_texts))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class HopCheck(FnsModel):
    """What a probe asks the platform about this hop: ``action`` at ``scope``."""

    action: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    data_plane: bool


class PathStep(FnsModel):
    rule: str = Field(min_length=1, max_length=64)
    """``assume-compromised``, ``snapshot``, an escalation rule, or the final way."""
    text: str = Field(min_length=1)
    sources: tuple[str, ...] = ()
    """Snapshot facts this hop rests on, with the scope operation that collected them."""
    check: HopCheck | None = None
    """Set on a final hop that rests on an RBAC grant (M3 probes it)."""


class ReachPath(FnsModel):
    id: str = Field(pattern=r"^[0-9a-f]{64}$")
    finding_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    rank: NonNegativeInt
    """0 is the shortest path; higher ranks are alternatives."""
    rung: Rung = "modeled"
    steps: tuple[PathStep, ...] = Field(min_length=1)
    assumptions: tuple[str, ...] = ()
    partial: bool = False
    """The grant covers only part of the target (a child scope, or owned objects)."""

    @model_validator(mode="after")
    def _id_matches(self) -> ReachPath:
        if self.id != path_id(self.finding_id, tuple(s.text for s in self.steps)):
            raise ValueError("path id does not match its finding and steps")
        return self


class FrontDoor(FnsModel):
    """An outside party that can sign in as an identity in this blast radius.

    From a federated identity credential (queue item 2, pending review). It adds no
    reach for the compromised identity and changes no verdict: it says who else can
    start from this identity. Modeled from the credential's issuer and subject
    only, not validated live.
    """

    identity: str = Field(min_length=1)
    """Object ID of the service principal the party signs in as."""
    identity_name: str | None = None
    application: str = Field(min_length=1)
    """Object ID of the application that holds the credential."""
    credential: str = Field(min_length=1)
    issuer: str = Field(min_length=1)
    subject: str | None = None
    kind: str = Field(min_length=1, max_length=64)
    severity: Literal["high", "medium", "unknown"]
    party: str = Field(min_length=1)
    reasons: tuple[str, ...] = Field(min_length=1)
    sources: tuple[str, ...] = Field(min_length=1)
    """Documentation the classification rests on."""

    def sort_key(self) -> tuple[int, str, str, str]:
        rank = {"high": 0, "medium": 1, "unknown": 2}[self.severity]
        return (rank, self.identity, self.application, self.credential)


class ReportSummary(FnsModel):
    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"unaccepted_inconclusive"})

    critical: NonNegativeInt
    """Failed must_not_reach findings."""
    max_critical_reachable: NonNegativeInt
    still_do_failed: NonNegativeInt
    inconclusive: NonNegativeInt
    max_inconclusive: NonNegativeInt
    on_inconclusive: Literal["fail", "warn"]
    exit_code: Literal[0, 1, 3]
    warning: str | None = None
    unaccepted_inconclusive: tuple[str, ...] = ()
    """Inconclusive items the budget does not name (``budget.accepted_inconclusive``)."""


class ContainReport(FnsModel):
    __volatile__: ClassVar[frozenset[str]] = frozenset({"generated_at", "tool_version"})
    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"front_doors"})

    version: Literal[1]
    mode: Literal["LIVE", "FIXTURE"]
    contract: str = Field(min_length=1)
    contract_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_digest: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    tenant_id: str
    semantics_version: NonNegativeInt
    compromised: str | None
    """Object ID of the assumed-compromised identity, or None if it did not resolve."""
    compromised_name: str | None = None
    generated_at: TzDatetime
    tool_version: str
    findings: tuple[Finding, ...]
    paths: tuple[ReachPath, ...] = ()
    front_doors: tuple[FrontDoor, ...] = ()
    summary: ReportSummary

    @field_validator("front_doors")
    @classmethod
    def _sort_front_doors(cls, v: tuple[FrontDoor, ...]) -> tuple[FrontDoor, ...]:
        keys = [f.sort_key() for f in v]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate front door")
        return tuple(sorted(v, key=lambda f: f.sort_key()))

    @field_validator("paths")
    @classmethod
    def _sort_paths(cls, v: tuple[ReachPath, ...]) -> tuple[ReachPath, ...]:
        if len({p.id for p in v}) != len(v):
            raise ValueError("duplicate path id")
        return tuple(sorted(v, key=lambda p: (p.finding_id, p.rank)))

    @model_validator(mode="after")
    def _references(self) -> ContainReport:
        finding_ids = {f.id for f in self.findings}
        if len(finding_ids) != len(self.findings):
            raise ValueError("duplicate finding id")
        path_ids = {p.id for p in self.paths}
        for p in self.paths:
            if p.finding_id not in finding_ids:
                raise ValueError(f"path {p.id[:12]} references an unknown finding")
        for f in self.findings:
            for e in f.evidence:
                if e.path_id is not None and e.path_id not in path_ids:
                    raise ValueError(f"finding {f.id[:12]} references an unknown path")
            if f.verdict == "pass":
                raise ValueError("a ContainReport never passes a finding (modeled evidence only)")
        return self
