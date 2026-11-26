"""Strict ARM resource ID parser.

ARM IDs are case-insensitive, so the canonical form is fully lowercased. The
parser is deliberately strict because the scope gate relies on it: anything
it does not understand is rejected rather than guessed at.

Accepted shapes (``<ext>`` = zero or more ``/providers/<ns>/<type>/<name>(/<type>/<name>)*``):

    /providers/<ns>/<type>/<name>...                          tenant-level provider resource
    /providers/Microsoft.Management/managementGroups/<mg><ext>
    /subscriptions/<guid><ext>
    /subscriptions/<guid>/resourceGroups/<rg><ext>

Rejected: empty segments (``//``), trailing ``/``, ``.``/``..`` segments,
percent-encoding, whitespace, non-ASCII, and any character outside a small
allowlist.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Literal

ArmLevel = Literal["tenant", "managementGroup", "subscription", "resourceGroup", "resource"]

GUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_\-.()$~]+$")
_NAMESPACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)+$")
_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_MAX_LEN = 2048


class ArmIdError(ValueError):
    """Raised for anything that is not a well-formed ARM resource ID."""


@dataclass(frozen=True, slots=True)
class ProviderPath:
    """``/providers/<namespace>/<type>/<name>(/<type>/<name>)*`` (lowercased)."""

    namespace: str
    pairs: tuple[tuple[str, str], ...]

    def format(self) -> str:
        tail = "".join(f"/{t}/{n}" for t, n in self.pairs)
        return f"/providers/{self.namespace}{tail}"


@dataclass(frozen=True, slots=True)
class ArmPath:
    """A parsed, lowercased ARM ID."""

    management_group: str | None
    subscription_id: uuid.UUID | None
    resource_group: str | None
    providers: tuple[ProviderPath, ...]

    @property
    def level(self) -> ArmLevel:
        """Where the ID lives. Anything under a management group or the tenant root
        reports that level; provider resources under a subscription report ``resource``
        (with ``resource_group`` None when they sit directly on the subscription)."""
        if self.subscription_id is None:
            return "tenant" if self.management_group is None else "managementGroup"
        if self.providers:
            return "resource"
        if self.resource_group is not None:
            return "resourceGroup"
        return "subscription"

    @property
    def resource_group_id(self) -> str | None:
        if self.subscription_id is None or self.resource_group is None:
            return None
        return f"/subscriptions/{self.subscription_id}/resourcegroups/{self.resource_group}"

    def format(self) -> str:
        parts: list[str] = []
        if self.management_group is not None:
            parts.append(
                f"/providers/microsoft.management/managementgroups/{self.management_group}"
            )
        if self.subscription_id is not None:
            parts.append(f"/subscriptions/{self.subscription_id}")
        if self.resource_group is not None:
            parts.append(f"/resourcegroups/{self.resource_group}")
        parts.extend(p.format() for p in self.providers)
        return "".join(parts)


def _check_segment(seg: str) -> str:
    if seg in {".", ".."} or not _SEGMENT_RE.fullmatch(seg):
        raise ArmIdError(f"invalid ARM ID segment {seg!r}")
    return seg.lower()


def _parse_providers(segs: list[str], i: int) -> tuple[tuple[ProviderPath, ...], int]:
    providers: list[ProviderPath] = []
    while i < len(segs):
        if segs[i].lower() != "providers":
            raise ArmIdError(f"expected 'providers' at segment {i}, got {segs[i]!r}")
        if i + 1 >= len(segs):
            raise ArmIdError("'providers' without a namespace")
        namespace = segs[i + 1]
        if not _NAMESPACE_RE.fullmatch(namespace):
            raise ArmIdError(f"invalid resource provider namespace {namespace!r}")
        j = i + 2
        pairs: list[tuple[str, str]] = []
        while j < len(segs) and segs[j].lower() != "providers":
            if j + 1 >= len(segs):
                raise ArmIdError(f"resource type {segs[j]!r} has no name")
            rtype, name = segs[j], segs[j + 1]
            if not _TYPE_RE.fullmatch(rtype):
                raise ArmIdError(f"invalid resource type {rtype!r}")
            pairs.append((rtype.lower(), _check_segment(name)))
            j += 2
        if not pairs:
            raise ArmIdError(f"provider {namespace!r} without a resource type/name")
        providers.append(ProviderPath(namespace.lower(), tuple(pairs)))
        i = j
    return tuple(providers), i


def parse_arm_id(value: object) -> ArmPath:
    """Parse an ARM ID. Raises :class:`ArmIdError` on anything malformed."""
    if not isinstance(value, str):
        raise ArmIdError("ARM ID must be a string")
    if not value or len(value) > _MAX_LEN:
        raise ArmIdError("ARM ID is empty or too long")
    if not value.isascii() or any(c.isspace() for c in value) or "%" in value:
        raise ArmIdError("ARM ID contains non-ASCII, whitespace or percent-encoding")
    if not value.startswith("/") or value.endswith("/"):
        raise ArmIdError("ARM ID must start with '/' and must not end with '/'")
    segs = value[1:].split("/")
    if any(s == "" for s in segs):
        raise ArmIdError("ARM ID contains an empty segment")
    for s in segs:
        _check_segment(s)

    mg: str | None = None
    sub: uuid.UUID | None = None
    rg: str | None = None
    i = 0
    head = segs[0].lower()
    if head == "subscriptions":
        if len(segs) < 2 or not GUID_RE.fullmatch(segs[1]):
            raise ArmIdError("subscription ID must be a GUID")
        sub = uuid.UUID(segs[1])
        i = 2
        if i < len(segs) and segs[i].lower() == "resourcegroups":
            if i + 1 >= len(segs):
                raise ArmIdError("'resourceGroups' without a name")
            rg = _check_segment(segs[i + 1])
            i += 2
    elif (
        head == "providers"
        and len(segs) >= 4
        and segs[1].lower() == "microsoft.management"
        and segs[2].lower() == "managementgroups"
    ):
        mg = _check_segment(segs[3])
        i = 4
    elif head != "providers":
        raise ArmIdError(f"ARM ID must start with /subscriptions or /providers, got /{segs[0]}")

    providers, i = _parse_providers(segs, i)
    if mg is None and sub is None and not providers:
        raise ArmIdError("ARM ID has no scope")
    return ArmPath(mg, sub, rg, providers)


def normalize_arm_id(value: object) -> str:
    return parse_arm_id(value).format()
