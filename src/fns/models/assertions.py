"""Frozen assertions: what a ``fns prove`` run will accept as proof, fixed before it runs.

An :class:`AssertionSet` is built from a contain report and a snapshot, written as
canonical JSON, and its sha256 is journaled before any probe runs. The verifier
reads only this file, the journal and the probe artifacts (docs/milestones/M3.md).
"""

from __future__ import annotations

import hashlib
from typing import ClassVar, Literal

from pydantic import Field, NonNegativeInt, field_validator, model_validator

from fns.models.base import FnsModel
from fns.models.evidence import ItemKind, Outcome
from fns.models.ids import TzDatetime

Hex64 = str
ProbeKind = Literal["arm-permissions", "data-read"]
ProbeRung = Literal["evaluated", "observed"]
ProbePurpose = Literal["direct", "hop"]

PROBE_RUNG: dict[str, ProbeRung] = {"arm-permissions": "evaluated", "data-read": "observed"}


def probe_id(assertion_id: str, kind: str, target: str, action: str) -> str:
    text = "\x1f".join((assertion_id, kind, target.lower(), action.lower()))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ProbeSpec(FnsModel):
    id: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    kind: ProbeKind
    rung: ProbeRung
    purpose: ProbePurpose
    """``direct`` asks about the contract operation itself; ``hop`` about a path's action."""
    target: str = Field(min_length=1)
    """ARM ID the probe addresses (the permissions scope, or the data-plane resource)."""
    action: str = Field(min_length=1)
    """RBAC (data) action for ``arm-permissions``; the contract operation for ``data-read``."""
    data_plane: bool = False
    scope_operation: str | None = None
    """The scope-gate operation a live probe calls; None while none exists (M3 E3)."""

    @model_validator(mode="after")
    def _consistent(self) -> ProbeSpec:
        if self.rung != PROBE_RUNG[self.kind]:
            raise ValueError(f"{self.kind} probes produce rung {PROBE_RUNG[self.kind]}")
        return self


class PathAssertion(FnsModel):
    path_id: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    summary: str = Field(min_length=1)
    """The path's rules, e.g. ``assume-compromised -> kv-control-to-data``."""
    refuted_by: tuple[Hex64, ...] = ()
    """Probe ids; any one of them returning ``denied`` refutes this path. Empty: the
    path cannot be refuted by a non-destructive probe (an escalation hop)."""

    @field_validator("refuted_by")
    @classmethod
    def _sorted(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(v)))


class Assertion(FnsModel):
    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"target_object_id"})

    finding_id: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    item_kind: ItemKind
    target: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    modeled_outcome: Outcome
    """What the model said: ``allowed`` (reachable), ``denied`` or ``unknown``."""
    modeled_reasons: tuple[str, ...] = ()
    paths: tuple[PathAssertion, ...] = ()
    probes: tuple[ProbeSpec, ...] = ()
    open_surfaces: tuple[str, ...] = ()
    """Uncollected surfaces that could add reach for this operation (blocks a pass, E1)."""
    target_object_id: str | None = Field(
        default=None, pattern=r"^(?:[0-9a-f-]{36}|/subscriptions/[^\s?#]+)$"
    )
    """The target's object at freeze, from the snapshot: the directory object ID of an
    ``application:`` or ``service_principal:`` target, or the normalized ARM ID of a
    ``resource:`` target. An after-harden strike counts toward a verdict only on this
    exact object (option B, approved 2026-11-27)."""

    @field_validator("paths")
    @classmethod
    def _sort_paths(cls, v: tuple[PathAssertion, ...]) -> tuple[PathAssertion, ...]:
        return tuple(sorted(v, key=lambda p: p.path_id))

    @field_validator("probes")
    @classmethod
    def _sort_probes(cls, v: tuple[ProbeSpec, ...]) -> tuple[ProbeSpec, ...]:
        return tuple(sorted(v, key=lambda p: p.id))

    @field_validator("open_surfaces")
    @classmethod
    def _sort_surfaces(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(v)))

    @model_validator(mode="after")
    def _references(self) -> Assertion:
        ids = [p.id for p in self.probes]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate probe id")
        unknown = {r for p in self.paths for r in p.refuted_by} - set(ids)
        if unknown:
            raise ValueError(f"path refers to unknown probe(s) {sorted(unknown)}")
        return self


class Thresholds(FnsModel):
    max_critical_reachable: NonNegativeInt
    max_inconclusive: NonNegativeInt
    on_inconclusive: Literal["fail", "warn"]


class AssertionSet(FnsModel):
    __volatile__: ClassVar[frozenset[str]] = frozenset({"frozen_at"})

    version: Literal[1]
    mode: Literal["LIVE", "FIXTURE"]
    run_id: str = Field(pattern=r"^[0-9a-f]{16,64}$")
    contract: str = Field(min_length=1)
    contract_digest: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_digest: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    report_digest: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    tenant_id: str
    compromised: str | None
    compromised_name: str | None = None
    thresholds: Thresholds
    frozen_at: TzDatetime
    assertions: tuple[Assertion, ...]

    @field_validator("assertions")
    @classmethod
    def _sort(cls, v: tuple[Assertion, ...]) -> tuple[Assertion, ...]:
        return tuple(sorted(v, key=lambda a: a.finding_id))

    @model_validator(mode="after")
    def _unique(self) -> AssertionSet:
        ids = [a.finding_id for a in self.assertions]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate assertion")
        probes = [p.id for a in self.assertions for p in a.probes]
        if len(probes) != len(set(probes)):
            raise ValueError("probe id shared between assertions")
        return self

    def probe(self, pid: str) -> tuple[Assertion, ProbeSpec] | None:
        for a in self.assertions:
            for p in a.probes:
                if p.id == pid:
                    return a, p
        return None

    def file_bytes(self) -> bytes:
        """Exactly what is written to ``assertions.json`` (and hashed into the journal)."""
        return (self.canonical_json() + "\n").encode("utf-8")


class ProbeObservation(FnsModel):
    """What one probe saw; stored content-addressed under ``artifacts/``."""

    __volatile__: ClassVar[frozenset[str]] = frozenset({"observed_at", "request_id"})

    version: Literal[1]
    mode: Literal["LIVE", "FIXTURE"]
    probe_id: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    finding_id: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    kind: ProbeKind
    rung: ProbeRung
    outcome: Outcome
    detail: str = ""
    """e.g. ``HTTP 403 Forbidden`` or ``action listed in permissions``; no secret values."""
    http_status: int | None = None
    request_id: str | None = None
    observed_at: TzDatetime

    def file_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


StrikeItemOutcome = Literal["allowed", "denied"]


def strike_step_key(write_key: str, item: str) -> str:
    """The journal step of one strike observation: ``strike:<sha256 of key and item>``."""
    text = "\x1f".join((write_key, item))
    return "strike:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class StrikeObservation(FnsModel):
    """One after-harden attempt (D-1 to D-7) as evidence for one contract item (D6).

    Written by ``fns prove --after-strike`` from a ``fns strike run`` and stored
    content-addressed under ``artifacts/`` like a probe observation. The verifier
    may only add it to a finding as context (a denial), or make the finding
    stricter (a success fails it). A LIVE 403 on the item's exact operation and
    object counts like an observed probe denial (option B, approved 2026-11-27):
    the verifier decides that, from ``request_operation`` and ``request_object_id``.
    """

    __volatile__: ClassVar[frozenset[str]] = frozenset({"observed_at", "request_id"})
    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"request_operation", "request_object_id"})

    version: Literal[1]
    mode: Literal["LIVE", "FIXTURE"]
    strike_run_id: str = Field(pattern=r"^[a-z0-9-]{8,40}$")
    plan_sha256: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    write_key: str = Field(pattern=r"^[A-Z0-9-]+/[a-z0-9-]+$")
    strike: str = Field(pattern=r"^D-[1-9]$")
    target: str = Field(min_length=1)
    """The contract item's target, e.g. ``application:id-verifier``."""
    operation: str = Field(min_length=1)
    outcome: StrikeItemOutcome
    http_status: int | None = None
    request_id: str | None = None
    observed_at: TzDatetime
    request_operation: str | None = None
    """The planned write's operation, e.g. ``graph:POST /applications/{id}/addPassword``."""
    request_object_id: str | None = Field(
        default=None, pattern=r"^(?:[0-9a-f-]{36}|/subscriptions/[^\s?#]+)$"
    )
    """The object the planned write names: a directory object ID (lower case), or a
    normalized ARM resource ID."""

    @property
    def step_key(self) -> str:
        return strike_step_key(self.write_key, f"{self.target} {self.operation}")

    def file_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")
