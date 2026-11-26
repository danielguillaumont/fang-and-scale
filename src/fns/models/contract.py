"""Blast-radius contracts (``contracts/*.fns.yaml``).

A contract declares what an assumed-compromised identity must never reach and
what it must still be able to do. Targets may be short names (resolved
against a snapshot in M2; ambiguous or unresolved means ``inconclusive``) or
full ARM IDs. Contract operations describe the attacker's capabilities and are
a different vocabulary from scope operations (the tool's own API calls).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Discriminator, Field, NonNegativeInt, Tag, field_validator, model_validator

from fns.models.base import FnsModel
from fns.yamlio import load_yaml

ContractOperation = Annotated[
    str,
    Field(
        pattern=r"^[A-Za-z][A-Za-z0-9]*(/[A-Za-z][A-Za-z0-9]*)*$",
        max_length=200,
        description="Capability, e.g. secrets/get, listKeys, blob/read, roleAssignments/write",
    ),
]

IdentityRef = Annotated[
    str,
    Field(
        pattern=(
            r"^((sp|mi):[A-Za-z0-9][A-Za-z0-9._\-]{0,255}"
            r"|objectId:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})$"
        ),
        description="sp:<name or appId>, mi:<name>, or objectId:<guid>",
    ),
]

TargetName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=2048,
        pattern=r"^[A-Za-z0-9/._\-()$~]+$",
        description="Resource name or full ARM ID",
    ),
]


def _sorted_unique_ops(v: tuple[str, ...]) -> tuple[str, ...]:
    if len({op.lower() for op in v}) != len(v):
        raise ValueError("duplicate operation")
    return tuple(sorted(v, key=str.lower))


class ResourceTarget(FnsModel):
    resource: TargetName
    operations: tuple[ContractOperation, ...] = Field(min_length=1)

    @field_validator("operations")
    @classmethod
    def _ops(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique_ops(v)

    @property
    def target_key(self) -> str:
        return f"resource:{self.resource.lower()}"


class DirectoryTarget(FnsModel):
    directory: Literal["tenant"]
    """The Entra directory of the pinned tenant."""
    operations: tuple[ContractOperation, ...] = Field(min_length=1)

    @field_validator("operations")
    @classmethod
    def _ops(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique_ops(v)

    @property
    def target_key(self) -> str:
        return f"directory:{self.directory}"


def _reach_kind(v: Any) -> str | None:
    if isinstance(v, dict):
        if "resource" in v:
            return "resource"
        if "directory" in v:
            return "directory"
        return None
    if isinstance(v, ResourceTarget):
        return "resource"
    if isinstance(v, DirectoryTarget):
        return "directory"
    return None


ReachItem = Annotated[
    Annotated[ResourceTarget, Tag("resource")] | Annotated[DirectoryTarget, Tag("directory")],
    Discriminator(_reach_kind),
]


class StillDoItem(ResourceTarget):
    source: Literal["declared", "recorded"] = "declared"
    """declared by hand, or recorded from the workload's own logged activity (M4)."""


class ContractThresholds(FnsModel):
    """Contract-level limits (YAML key ``budget``). Semantics are applied in M2."""

    max_critical_reachable: NonNegativeInt = 0
    max_inconclusive: NonNegativeInt = 0


class Contract(FnsModel):
    """A blast-radius contract."""

    version: Literal[1]
    contract: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    """Contract name (lowercase slug)."""
    assume_compromised: IdentityRef
    must_not_reach: tuple[ReachItem, ...] = Field(min_length=1)
    must_still_do: tuple[StillDoItem, ...] = ()
    budget: ContractThresholds = ContractThresholds()
    on_inconclusive: Literal["fail", "warn"] = "fail"

    @field_validator("must_not_reach")
    @classmethod
    def _sort_reach(
        cls, v: tuple[ResourceTarget | DirectoryTarget, ...]
    ) -> tuple[ResourceTarget | DirectoryTarget, ...]:
        keys = [i.target_key for i in v]
        if len(set(keys)) != len(keys):
            raise ValueError("each must_not_reach target must be listed once")
        return tuple(sorted(v, key=lambda i: i.target_key))

    @field_validator("must_still_do")
    @classmethod
    def _sort_still(cls, v: tuple[StillDoItem, ...]) -> tuple[StillDoItem, ...]:
        keys = [i.target_key for i in v]
        if len(set(keys)) != len(keys):
            raise ValueError("each must_still_do target must be listed once")
        return tuple(sorted(v, key=lambda i: i.target_key))

    @model_validator(mode="after")
    def _no_contradictions(self) -> Contract:
        forbidden = {(i.target_key, op.lower()) for i in self.must_not_reach for op in i.operations}
        both = sorted(
            f"{key} {op}"
            for i in self.must_still_do
            for op in i.operations
            if ((key := i.target_key), op.lower()) in forbidden
        )
        if both:
            raise ValueError(f"operations in both must_not_reach and must_still_do: {both}")
        return self


def load_contract(path: Path) -> Contract:
    return Contract.model_validate(load_yaml(path))
