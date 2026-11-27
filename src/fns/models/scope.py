"""``scope.yaml``: what the tool itself is allowed to touch.

Deny by default: a missing verb, an empty list or an expired manifest allows
nothing. The model never reads the wall clock; expiry is checked by
:func:`load_scope` and again by the gate on every call.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated, ClassVar, Final, Literal

from pydantic import AfterValidator, Field, PositiveInt, field_validator, model_validator

from fns.models.armid import GUID_RE, parse_arm_id
from fns.models.base import FnsModel
from fns.models.firstparty import is_first_party
from fns.models.ids import ArmId, Guid, TzDatetime
from fns.models.operations import WRITE_FORM_KEYS, OperationError, parse_operation
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
        description=(
            "arm:<Namespace>/<type>/<read|write|delete|action>, graph:<METHOD> /<path>, "
            "kv:GET /secrets[/<name>] or blob:HEAD /<container>/<blob>"
        ),
        pattern=r"^(arm:\S+|graph:(GET|POST|PUT|PATCH|DELETE) /\S+|kv:GET /\S+|blob:HEAD /\S+)$",
    ),
]


class TestIdentity(FnsModel):
    """An identity the executor may act as (``strike``)."""

    __test__: ClassVar[bool] = False  # not a pytest test class
    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"app_id"})

    object_id: Guid
    """Entra object ID of the service principal or managed identity."""
    kind: Literal["servicePrincipal", "managedIdentity"]
    name: str = Field(min_length=1, max_length=256)
    app_id: Guid | None = None
    """Application (client) ID. When set, ``fns prove --live`` also requires the
    token's ``appid`` to match it (decision V4)."""


DATA_PLANE_VERB: Final = "prove"
"""The only verb that may read a data plane (M3 P5.1)."""

DATA_RESOURCE_TYPES: Final[dict[str, tuple[str, str]]] = {
    "kv": ("microsoft.keyvault", "vaults"),
    "blob": ("microsoft.storage", "storageaccounts"),
}
"""The resource type each data-plane API acts on (provider namespace, type)."""


def data_resource(resource_id: str) -> tuple[str, str] | None:
    """``(api, name)`` if the ID is exactly a vault or storage account, else None."""
    path = parse_arm_id(resource_id)
    if path.level != "resource" or path.resource_group is None or len(path.providers) != 1:
        return None
    provider = path.providers[0]
    if len(provider.pairs) != 1:
        return None
    rtype, name = provider.pairs[0]
    for api, (ns, t) in DATA_RESOURCE_TYPES.items():
        if (provider.namespace, rtype) == (ns, t):
            return api, name
    return None


class DataObject(FnsModel):
    """One data-plane object ``prove`` may read, bound to the resource that holds it.

    A data-plane call is allowed only if its operation is listed under ``prove`` *and*
    its (resource, path) pair is listed here, so a scope cannot read the payroll blob
    path from the invoices account, or a secret from another vault.
    """

    resource: ArmId
    """The vault or storage account (full ARM ID)."""
    operation: ScopeOperation
    """``kv:GET /secrets/<name>`` or ``blob:HEAD /<container>/<blob>``."""

    @model_validator(mode="after")
    def _kind(self) -> DataObject:
        op = parse_operation(self.operation)
        found = data_resource(self.resource)
        if not op.is_data_plane or op.path == "/secrets":
            raise ValueError("a data object names one secret or one blob")
        if found is None or found[0] != op.api:
            raise ValueError(f"{op.api} object on a resource that is not a {op.api} resource")
        return self


StrikeTargetKind = Literal["arm", "graph-application", "graph-service-principal"]


class StrikeTarget(FnsModel):
    """One object ``strike`` may write to (M4 strike plan, "Lab objects only").

    Rendered by Terraform from the lab's own resources, never hand-written. A Graph
    target also has to pass a live check (its lab tags and display name) before the
    gate allows the first write to it.
    """

    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"display_name", "application"})

    kind: StrikeTargetKind
    id: str = Field(min_length=1, max_length=2048)
    """A full ARM ID (``arm``: a vault or a storage account) or an Entra object ID."""
    display_name: str | None = Field(default=None, min_length=1, max_length=256)
    """Graph targets: the display name Terraform gave the object; the live check
    compares it."""
    application: Guid | None = None
    """Service principals: the object ID of its application, also a target."""

    @model_validator(mode="after")
    def _shape(self) -> StrikeTarget:
        if self.kind == "arm":
            if data_resource(self.id) is None:
                raise ValueError("an arm strike target is exactly one vault or storage account")
            if self.display_name is not None or self.application is not None:
                raise ValueError("an arm strike target has no display_name or application")
            return self
        if not GUID_RE.fullmatch(self.id):
            raise ValueError(f"a {self.kind} target id is an object ID (GUID)")
        if is_first_party(self.id):
            raise ValueError("a strike target can never be a Microsoft first-party object")
        if self.display_name is None:
            raise ValueError(f"a {self.kind} target needs its display_name")
        if (self.kind == "graph-service-principal") != (self.application is not None):
            raise ValueError("a service principal target, and only one, names its application")
        return self

    @property
    def key(self) -> str:
        """Canonical ID: lowercased ARM ID or canonical GUID."""
        if self.kind == "arm":
            return parse_arm_id(self.id).format()
        return str(uuid.UUID(self.id))


class StrikeEscalation(FnsModel):
    """S4 (approved 2026-11-27): the one identity other than a test identity a strike
    may act as, and the one thing it may do.

    Absent means no token request and no write as anyone but a test identity. The
    gate allows the escalated identity only to assign this marker role to a test
    identity on its own service principal, and to remove that assignment.
    """

    service_principal: Guid
    """The escalation target's service principal (``app-escalation-target``). It must
    be a ``graph-service-principal`` strike target, and never a test identity."""
    marker_role_id: Guid
    """The marker app role Terraform defines on that service principal's application
    (``lab/identities.tf``); the gate checks it live before S4 may assign it."""


class StrikeScope(FnsModel):
    """The ``strike:`` block: which lab objects strikes may write, and until when."""

    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"escalation"})

    expires_at: TzDatetime
    """Strike writes stop at this instant, even if the manifest is still valid."""
    targets: tuple[StrikeTarget, ...] = Field(min_length=1)
    escalation: StrikeEscalation | None = None
    """S4 only (``lab/scope.tf`` renders it with ``enable_strikes``)."""

    @model_validator(mode="after")
    def _escalation(self) -> StrikeScope:
        e = self.escalation
        if e is None:
            return self
        sp = str(e.service_principal)
        if not any(t.kind == "graph-service-principal" and t.key == sp for t in self.targets):
            raise ValueError("strike.escalation names a service principal that is not a target")
        if is_first_party(str(e.marker_role_id)):
            raise ValueError("the marker role can never be a Microsoft first-party ID")
        return self

    @field_validator("targets")
    @classmethod
    def _targets(cls, v: tuple[StrikeTarget, ...]) -> tuple[StrikeTarget, ...]:
        keys = [t.key for t in v]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate strike target")
        apps = {t.key for t in v if t.kind == "graph-application"}
        for t in v:
            if t.application is not None and str(t.application) not in apps:
                raise ValueError(f"service principal {t.key}: its application is not a target")
        return tuple(sorted(v, key=lambda t: (t.kind, t.key)))


class ScopeBudget(FnsModel):
    """Per-run limits enforced by the gate."""

    max_api_calls: PositiveInt
    max_minutes: PositiveInt


class ScopeManifest(FnsModel):
    """The scope manifest (``scope.yaml``)."""

    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"data_objects", "strike"})

    version: Literal[1]
    tenant_id: Guid
    """The only tenant any call may target. The signed-in tenant must match."""
    subscription_ids: tuple[Guid, ...] = ()
    allowed_resource_groups: tuple[ArmId, ...] = ()
    """Full resource group IDs (/subscriptions/<id>/resourceGroups/<name>)."""
    test_identities: tuple[TestIdentity, ...] = ()
    allowed_operations: dict[Verb, tuple[ScopeOperation, ...]] = Field(default_factory=dict)
    """Exact operations per verb. A missing verb allows nothing."""
    data_objects: tuple[DataObject, ...] = ()
    """Data-plane objects ``prove`` may read. Empty means no data-plane call at all."""
    strike: StrikeScope | None = None
    """Lab objects ``strike`` may write to (M4). Absent means no write at all."""
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
            data = [op for op in ops if parse_operation(op).is_data_plane]
            if data and verb != DATA_PLANE_VERB:
                raise ValueError(f"data-plane operations are allowed only under prove: {data}")
            if verb == "strike":
                unknown = [
                    op
                    for op in ops
                    if not parse_operation(op).is_read
                    and parse_operation(op).key not in WRITE_FORM_KEYS
                ]
                if unknown:
                    raise ValueError(f"strike may list only the M4 write forms, not: {unknown}")
            if verb in READ_ONLY_VERBS:
                writes = [op for op in ops if not parse_operation(op).is_read]
                if writes:
                    raise ValueError(
                        f"{verb} is read-only; non-read operations not allowed: {writes}"
                    )
            out[verb] = tuple(sorted(ops, key=lambda op: parse_operation(op).key))
        return out

    @field_validator("data_objects")
    @classmethod
    def _data_objects(cls, v: tuple[DataObject, ...]) -> tuple[DataObject, ...]:
        keys = [(parse_arm_id(d.resource).format(), parse_operation(d.operation).key) for d in v]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate data object")
        return tuple(d for _, d in sorted(zip(keys, v, strict=True), key=lambda kd: kd[0]))

    @model_validator(mode="after")
    def _data_objects_in_scope(self) -> ScopeManifest:
        rgs = {parse_arm_id(rg).format() for rg in self.allowed_resource_groups}
        listed = {parse_operation(op).key for op in self.allowed_operations.get("prove", ())}
        for d in self.data_objects:
            if parse_arm_id(d.resource).resource_group_id not in rgs:
                raise ValueError(f"data object {d.resource} is outside allowed_resource_groups")
            if parse_operation(d.operation).key not in listed:
                raise ValueError(f"data object operation {d.operation} is not listed under prove")
        return self

    @model_validator(mode="after")
    def _strike_targets_in_scope(self) -> ScopeManifest:
        if self.strike is None:
            return self
        rgs = {parse_arm_id(rg).format() for rg in self.allowed_resource_groups}
        tests = {str(i.object_id) for i in self.test_identities}
        for t in self.strike.targets:
            if t.kind == "arm" and parse_arm_id(t.id).resource_group_id not in rgs:
                raise ValueError(f"strike target {t.id} is outside allowed_resource_groups")
            if t.kind != "arm" and t.key == str(self.tenant_id):
                raise ValueError("the tenant itself is not a strike target")
            if t.kind == "graph-application" and t.key in tests:
                raise ValueError("an application object cannot be a test identity")
        e = self.strike.escalation
        if e is not None and str(e.service_principal) in tests:
            raise ValueError("the escalated identity (strike.escalation) is never a test identity")
        return self

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
