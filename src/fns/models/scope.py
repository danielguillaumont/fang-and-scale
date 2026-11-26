"""``scope.yaml``: what the tool itself is allowed to touch.

Deny by default: a missing verb, an empty list or an expired manifest allows
nothing. The model never reads the wall clock; expiry is checked by
:func:`load_scope` and again by the gate on every call.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated, ClassVar, Final, Literal

from pydantic import AfterValidator, Field, PositiveInt, field_validator, model_validator

from fns.models.armid import parse_arm_id
from fns.models.base import FnsModel
from fns.models.ids import ArmId, Guid, TzDatetime
from fns.models.operations import OperationError, parse_operation
from fns.yamlio import load_yaml, loads_yaml

Verb = Literal["scout", "contain", "strike", "harden", "prove", "molt"]
READ_ONLY_VERBS: Final[frozenset[str]] = frozenset({"scout", "contain", "prove", "molt"})


def _check_operation(value: str) -> str:
    try:
        parse_operation(value)
    except OperationError as exc:
        raise ValueError(str(exc)) from exc
    return value


ScopeOperation = Annotated[
    str,
    AfterValidator(_check_operation),
    Field(
        description="arm:<Namespace>/<type>/<read|write|delete|action> or graph:<METHOD> /<path>",
        pattern=r"^(arm:\S+|graph:(GET|POST|PUT|PATCH|DELETE) /\S+)$",
    ),
]


class TestIdentity(FnsModel):
    """An identity the executor may act as (``strike``)."""

    __test__: ClassVar[bool] = False  # not a pytest test class

    object_id: Guid
    """Entra object ID of the service principal or managed identity."""
    kind: Literal["servicePrincipal", "managedIdentity"]
    name: str = Field(min_length=1, max_length=256)


class ScopeBudget(FnsModel):
    """Per-run limits enforced by the gate."""

    max_api_calls: PositiveInt
    max_minutes: PositiveInt


class ScopeManifest(FnsModel):
    """The scope manifest (``scope.yaml``)."""

    version: Literal[1]
    tenant_id: Guid
    """The only tenant any call may target. The signed-in tenant must match."""
    subscription_ids: tuple[Guid, ...] = ()
    allowed_resource_groups: tuple[ArmId, ...] = ()
    """Full resource group IDs (/subscriptions/<id>/resourceGroups/<name>)."""
    test_identities: tuple[TestIdentity, ...] = ()
    allowed_operations: dict[Verb, tuple[ScopeOperation, ...]] = Field(default_factory=dict)
    """Exact operations per verb. A missing verb allows nothing."""
    budget: ScopeBudget
    expires_at: TzDatetime
    """After this instant the manifest allows nothing."""

    @field_validator("subscription_ids")
    @classmethod
    def _unique_subs(cls, v: tuple[Guid, ...]) -> tuple[Guid, ...]:
        if len(set(v)) != len(v):
            raise ValueError("duplicate subscription ID")
        return tuple(sorted(v))

    @field_validator("allowed_resource_groups")
    @classmethod
    def _rg_ids(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for rg in v:
            if parse_arm_id(rg).level != "resourceGroup":
                raise ValueError(f"{rg} is not a resource group ID")
        if len(set(v)) != len(v):
            raise ValueError("duplicate resource group")
        return tuple(sorted(v))

    @field_validator("test_identities")
    @classmethod
    def _unique_identities(cls, v: tuple[TestIdentity, ...]) -> tuple[TestIdentity, ...]:
        if len({i.object_id for i in v}) != len(v):
            raise ValueError("duplicate test identity object_id")
        return tuple(sorted(v, key=lambda i: str(i.object_id)))

    @field_validator("allowed_operations")
    @classmethod
    def _ops(cls, v: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
        out: dict[str, tuple[str, ...]] = {}
        for verb in sorted(v):
            ops = v[verb]
            keys = [parse_operation(op).key for op in ops]
            if len(set(keys)) != len(keys):
                raise ValueError(f"duplicate operation under {verb}")
            if verb in READ_ONLY_VERBS:
                writes = [op for op in ops if not parse_operation(op).is_read]
                if writes:
                    raise ValueError(
                        f"{verb} is read-only; non-read operations not allowed: {writes}"
                    )
            out[verb] = tuple(sorted(ops, key=lambda op: parse_operation(op).key))
        return out

    @model_validator(mode="after")
    def _rgs_in_subscriptions(self) -> ScopeManifest:
        subs = set(self.subscription_ids)
        for rg in self.allowed_resource_groups:
            if parse_arm_id(rg).subscription_id not in subs:
                raise ValueError(
                    f"resource group {rg} is in a subscription not listed in subscription_ids"
                )
        return self

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


class ScopeExpiredError(ValueError):
    """The manifest's ``expires_at`` has passed."""


def load_scope(path: Path, *, now: datetime) -> ScopeManifest:
    """Load and validate ``scope.yaml``. Expired means invalid."""
    return _checked(ScopeManifest.model_validate(load_yaml(path)), now)


def parse_scope(text: str, *, now: datetime) -> ScopeManifest:
    """Like :func:`load_scope`, from text (package resources, fixtures)."""
    return _checked(ScopeManifest.model_validate(loads_yaml(text)), now)


def _checked(manifest: ScopeManifest, now: datetime) -> ScopeManifest:
    if manifest.is_expired(now):
        raise ScopeExpiredError(f"scope manifest expired at {manifest.expires_at.isoformat()}")
    return manifest
