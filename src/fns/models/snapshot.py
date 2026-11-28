"""Inventory snapshot produced by ``fns scout``.

Determinism: entities are sorted by (id, type) and edges by (type, src, dst,
identity attributes); set-like lists are sorted; floats are rejected. The
digest excludes volatile fields (``collected_at``, ``collector_version``,
``provenance.observed_at``, ``provenance.request_id``, ``duration_ms``) but
includes ``mode``, so a FIXTURE snapshot can never share a LIVE digest.
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Final, Literal

from pydantic import Field, NonNegativeInt, field_validator, model_validator

from fns.models.armid import GUID_RE, ArmIdError, normalize_arm_id
from fns.models.base import FnsModel
from fns.models.ids import ArmId, Guid, TzDatetime

EntityType = Literal[
    "user",
    "servicePrincipal",
    "managedIdentity",
    "application",
    "group",
    "directoryRole",
    "roleDefinition",
    "resource",
    "scope",
]
GRAPH_ENTITY_TYPES: Final[frozenset[str]] = frozenset(
    {"user", "servicePrincipal", "managedIdentity", "application", "group", "directoryRole"}
)
ARM_ENTITY_TYPES: Final[frozenset[str]] = frozenset({"roleDefinition", "resource", "scope"})

TENANT_ROOT_SCOPE: Final = "/"
"""ARM's root scope (above the tenant root management group), e.g. elevated access."""

EVERYONE_PRINCIPAL_ID: Final = "00000000-0000-0000-0000-000000000000"
"""ARM deny assignments that apply to all principals use the all-zeros principal ID."""

AgentIdKind = Literal["agentIdentity", "agentIdentityBlueprint", "agentIdentityBlueprintPrincipal"]
AGENT_ID_PROPERTY: Final = "agentIdType"
"""Entity property set only on Entra Agent ID objects (docs/milestones/M6-agent-id.md).

The entity keeps its base type (``servicePrincipal`` or ``application``), so
nothing else in the model changes. The property marks what the model cannot
assess yet: the permissions an agent identity inherits from its blueprint."""
AGENT_ID_ODATA_TYPES: Final[dict[str, tuple[AgentIdKind, EntityType]]] = {
    "#microsoft.graph.agentIdentity": ("agentIdentity", "servicePrincipal"),
    "#microsoft.graph.agentIdentityBlueprint": ("agentIdentityBlueprint", "application"),
    "#microsoft.graph.agentIdentityBlueprintPrincipal": (
        "agentIdentityBlueprintPrincipal",
        "servicePrincipal",
    ),
}
"""Graph ``@odata.type`` -> (Agent ID kind, base entity type), from Microsoft Learn
(read 2026-11-27). How they appear in ``GET /servicePrincipals`` is V-A2."""
AGENT_ID_LABELS: Final[dict[str, str]] = {
    "agentIdentity": "an agent identity",
    "agentIdentityBlueprint": "an agent identity blueprint",
    "agentIdentityBlueprintPrincipal": "a blueprint principal",
}
AGENT_ID_NOT_MODELED: Final = "Agent ID inheritance not modeled"
"""The reason every finding gets when the attacker controls an Agent ID object."""

PropertyValue = str | int | bool | None | tuple[str, ...]
PropertyKey = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_.]{0,127}$")]
SetOfStr = tuple[str, ...]


def _sorted_set(v: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(v)))


class Entity(FnsModel):
    id: str = Field(min_length=1, max_length=2048)
    """Lowercased object GUID (Graph types) or lowercased ARM ID (ARM types)."""
    type: EntityType
    display_name: str | None = None
    properties: dict[PropertyKey, PropertyValue] = Field(default_factory=dict)

    @field_validator("properties")
    @classmethod
    def _sort_list_props(cls, v: dict[str, PropertyValue]) -> dict[str, PropertyValue]:
        return {
            k: (_sorted_set(val) if isinstance(val, tuple) else val) for k, val in sorted(v.items())
        }

    @model_validator(mode="before")
    @classmethod
    def _normalize_id(cls, data: object) -> object:
        if not isinstance(data, dict) or not isinstance(data.get("id"), str):
            return data
        raw: str = data["id"]
        etype = data.get("type")
        if etype in GRAPH_ENTITY_TYPES:
            if not GUID_RE.fullmatch(raw):
                raise ValueError(f"{etype} id must be an object GUID, got {raw!r}")
            return {**data, "id": raw.lower()}
        if etype == "scope" and raw == TENANT_ROOT_SCOPE:
            return data
        if etype in ARM_ENTITY_TYPES:
            try:
                return {**data, "id": normalize_arm_id(raw)}
            except ArmIdError as exc:
                raise ValueError(f"{etype} id must be an ARM ID: {exc}") from exc
        return data


class Provenance(FnsModel):
    __volatile__: ClassVar[frozenset[str]] = frozenset({"request_id", "observed_at"})

    source_api: str = Field(min_length=1, max_length=512)
    """The scope operation that produced this fact.

    e.g. ``arm:Microsoft.Authorization/roleAssignments/read``.
    """
    request_id: str | None = None
    observed_at: TzDatetime


class _EdgeBase(FnsModel):
    src: str = Field(min_length=1)
    dst: str = Field(min_length=1)
    provenance: Provenance

    @field_validator("src", "dst")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()

    def identity(self) -> tuple[str, ...]:
        """Extra attributes that distinguish parallel edges of the same type."""
        return ()

    def sort_key(self) -> tuple[str, ...]:
        type_: str = getattr(self, "type")  # noqa: B009 - defined on every subclass
        return (type_, self.src, self.dst, *self.identity())


class MemberOf(_EdgeBase):
    type: Literal["memberOf"]


class Owns(_EdgeBase):
    type: Literal["owns"]


class Contains(_EdgeBase):
    """Scope hierarchy: subscription -> resource group -> resource."""

    type: Literal["contains"]


class InstanceOf(_EdgeBase):
    """servicePrincipal -> application it instantiates (same appId)."""

    type: Literal["instanceOf"]


class HasIdentity(_EdgeBase):
    """ARM resource -> managed identity it runs as."""

    type: Literal["hasIdentity"]


class HasAppRole(_EdgeBase):
    """principal -> resource service principal (e.g. Microsoft Graph)."""

    type: Literal["hasAppRole"]
    app_role_id: Guid
    app_role_value: str | None = None
    """e.g. Application.ReadWrite.OwnedBy, resolved from the resource SP's appRoles."""
    assignment_id: str | None = None

    def identity(self) -> tuple[str, ...]:
        return (str(self.app_role_id),)


class HasDirectoryRole(_EdgeBase):
    """principal -> directoryRole (entity id = role definition/template GUID)."""

    type: Literal["hasDirectoryRole"]
    directory_scope_id: str = "/"
    """'/' for tenant-wide; '/<objectId>' for app- or AU-scoped assignments."""
    assignment_id: str | None = None

    def identity(self) -> tuple[str, ...]:
        return (self.directory_scope_id,)


class HasRbacRole(_EdgeBase):
    """principal -> scope entity (dst is the assignment scope)."""

    type: Literal["hasRbacRole"]
    role_definition_id: ArmId
    assignment_id: ArmId
    condition: str | None = None
    """ABAC condition; unsupported semantics make dependent findings inconclusive."""

    def identity(self) -> tuple[str, ...]:
        return (self.assignment_id,)


class DenyAssignment(_EdgeBase):
    """principal (or the all-zeros Everyone principal) -> scope entity."""

    type: Literal["denyAssignment"]
    deny_assignment_id: ArmId
    actions: SetOfStr = ()
    not_actions: SetOfStr = ()
    data_actions: SetOfStr = ()
    not_data_actions: SetOfStr = ()
    excluded_principal_ids: tuple[Guid, ...] = ()
    do_not_apply_to_child_scopes: bool = False

    @field_validator("actions", "not_actions", "data_actions", "not_data_actions")
    @classmethod
    def _sets(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_set(v)

    @field_validator("excluded_principal_ids")
    @classmethod
    def _guids(cls, v: tuple[Guid, ...]) -> tuple[Guid, ...]:
        return tuple(sorted(set(v), key=str))

    def identity(self) -> tuple[str, ...]:
        return (self.deny_assignment_id,)


class HasAccessPolicy(_EdgeBase):
    """principal -> Key Vault: a vault access policy (applies in access-policy mode only)."""

    type: Literal["hasAccessPolicy"]
    secrets: SetOfStr = ()
    keys: SetOfStr = ()
    certificates: SetOfStr = ()
    """Permission names as ARM returns them, lowercased (e.g. get, list, all)."""

    @field_validator("secrets", "keys", "certificates")
    @classmethod
    def _perms(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_set(tuple(p.lower() for p in v))


class HasEligibleRole(_EdgeBase):
    """principal -> role it is *eligible* for through PIM (not active).

    ``plane`` directory: dst is the Entra role definition (template GUID).
    ``plane`` arm: dst is the ARM scope; the role definition is an attribute.
    The reach model does not activate eligibility: it makes dependent findings
    inconclusive instead (M3 E1).
    """

    type: Literal["hasEligibleRole"]
    plane: Literal["directory", "arm"]
    role_definition_id: str = Field(min_length=1)
    directory_scope_id: str | None = None
    """'/' or '/<objectId>' for the directory plane; None for ARM."""
    schedule_id: str | None = None

    @field_validator("role_definition_id")
    @classmethod
    def _lower_role(cls, v: str) -> str:
        return v.lower()

    def identity(self) -> tuple[str, ...]:
        return (self.plane, self.role_definition_id, self.directory_scope_id or "")


Edge = Annotated[
    MemberOf
    | Owns
    | Contains
    | InstanceOf
    | HasIdentity
    | HasAppRole
    | HasDirectoryRole
    | HasRbacRole
    | DenyAssignment
    | HasAccessPolicy
    | HasEligibleRole,
    Field(discriminator="type"),
]

CredentialKind = Literal["key", "password"]
"""``key``: an entry of ``keyCredentials`` (a certificate or symmetric key);
``password``: an entry of ``passwordCredentials`` (a client secret)."""


class Credential(FnsModel):
    """Metadata of one key or password credential on an application or service principal.

    Never a value: Graph's ``key`` (certificate data), ``customKeyIdentifier``
    (thumbprint), ``hint`` (the first three characters of a password) and
    ``secretText`` have no field here, and ``extra="forbid"`` rejects them.
    """

    owner: str = Field(min_length=1)
    """Object ID of the application or service principal that holds the credential."""
    kind: CredentialKind
    key_id: Guid
    display_name: str | None = Field(default=None, max_length=1024)
    key_type: str | None = Field(default=None, max_length=64)
    """``keyCredential.type``, e.g. ``AsymmetricX509Cert``; None for passwords."""
    usage: str | None = Field(default=None, max_length=64)
    """``keyCredential.usage`` (``Verify`` or ``Sign``); None for passwords."""
    start: TzDatetime | None = None
    end: TzDatetime | None = None
    provenance: Provenance

    @field_validator("owner")
    @classmethod
    def _owner(cls, v: str) -> str:
        if not GUID_RE.fullmatch(v):
            raise ValueError(f"credential owner must be an object GUID, got {v!r}")
        return v.lower()

    def sort_key(self) -> tuple[str, str, str]:
        return (self.owner, self.kind, str(self.key_id))


CollectorStatus = Literal["complete", "partial", "failed", "skipped", "not-applicable"]
"""``not-applicable``: the surface the collector reads does not exist in this tenant,
with the evidence in ``coverage.not_applicable`` (never inferred)."""


class CollectorRun(FnsModel):
    __volatile__: ClassVar[frozenset[str]] = frozenset({"duration_ms"})

    name: str = Field(pattern=r"^[a-z][a-z0-9.\-]{0,63}$")
    status: CollectorStatus
    items: NonNegativeInt = 0
    error_codes: SetOfStr = ()
    """e.g. http-403, http-429-exhausted, scope-denied."""
    duration_ms: NonNegativeInt | None = None

    @field_validator("error_codes")
    @classmethod
    def _codes(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_set(v)


class NotCollected(FnsModel):
    surface: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class NotApplicable(FnsModel):
    """A surface that does not exist in this tenant, and the responses that show it."""

    surface: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    evidence: tuple[str, ...] = Field(min_length=1)
    """What was observed, e.g. the status and error code of a listing, and the
    subscribed SKUs. Order is the order of the requests."""


class SnapshotCoverage(FnsModel):
    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"not_applicable"})

    collectors: tuple[CollectorRun, ...] = ()
    not_collected: tuple[NotCollected, ...] = ()
    not_applicable: tuple[NotApplicable, ...] = ()
    """Surfaces shown not to exist; findings do not wait on them."""

    @field_validator("not_applicable")
    @classmethod
    def _not_applicable(cls, v: tuple[NotApplicable, ...]) -> tuple[NotApplicable, ...]:
        if len({n.surface for n in v}) != len(v):
            raise ValueError("duplicate not_applicable surface")
        return tuple(sorted(v, key=lambda n: n.surface))

    @model_validator(mode="after")
    def _exclusive(self) -> SnapshotCoverage:
        both = sorted(
            {n.surface for n in self.not_collected} & {n.surface for n in self.not_applicable}
        )
        if both:
            raise ValueError(f"a surface cannot be both not collected and not applicable: {both}")
        return self

    @field_validator("collectors")
    @classmethod
    def _collectors(cls, v: tuple[CollectorRun, ...]) -> tuple[CollectorRun, ...]:
        if len({c.name for c in v}) != len(v):
            raise ValueError("duplicate collector name")
        return tuple(sorted(v, key=lambda c: c.name))

    @field_validator("not_collected")
    @classmethod
    def _not_collected(cls, v: tuple[NotCollected, ...]) -> tuple[NotCollected, ...]:
        return tuple(sorted(set(v), key=lambda n: (n.surface, n.reason)))


class Snapshot(FnsModel):
    """A read-only inventory of one tenant + its in-scope subscriptions."""

    __volatile__: ClassVar[frozenset[str]] = frozenset({"collected_at", "collector_version"})
    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"credentials"})

    version: Literal[1]
    mode: Literal["LIVE", "FIXTURE"]
    tenant_id: Guid
    collected_at: TzDatetime
    collector_version: str
    entities: tuple[Entity, ...] = ()
    edges: tuple[Edge, ...] = ()
    credentials: tuple[Credential, ...] = ()
    """Key and password credential metadata (collected only when the scope allows the
    per-object reads; see ``graph.CREDENTIAL_OPERATIONS``)."""
    coverage: SnapshotCoverage = SnapshotCoverage()

    @field_validator("credentials")
    @classmethod
    def _sort_credentials(cls, v: tuple[Credential, ...]) -> tuple[Credential, ...]:
        keys = [c.sort_key() for c in v]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate credential")
        return tuple(sorted(v, key=lambda c: c.sort_key()))

    @field_validator("entities")
    @classmethod
    def _sort_entities(cls, v: tuple[Entity, ...]) -> tuple[Entity, ...]:
        ids = [e.id for e in v]
        if len(set(ids)) != len(ids):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate entity id(s): {dupes}")
        return tuple(sorted(v, key=lambda e: (e.id, e.type)))

    @field_validator("edges")
    @classmethod
    def _sort_edges(cls, v: tuple[_EdgeBase, ...]) -> tuple[_EdgeBase, ...]:
        keys = [e.sort_key() for e in v]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate edge")
        return tuple(sorted(v, key=lambda e: e.sort_key()))

    @model_validator(mode="after")
    def _no_dangling_edges(self) -> Snapshot:
        known = {e.id for e in self.entities}
        dangling = sorted(
            f"{e.type} {end}" for e in self.edges for end in (e.src, e.dst) if end not in known
        )
        if dangling:
            raise ValueError(f"edges reference unknown entities: {dangling[:5]}")
        orphans = sorted({c.owner for c in self.credentials if c.owner not in known})
        if orphans:
            raise ValueError(f"credentials reference unknown entities: {orphans[:5]}")
        return self
