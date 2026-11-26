"""Gate targets and request-URL checks.

A target is what a call acts on: an ARM scope/resource, or the tenant's Entra
directory. Request URLs are checked separately so a pagination ``nextLink``
(untrusted API output, PLAN.md section 9) cannot move a call to another host
or another path.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from fns.models.armid import ArmIdError, ArmPath, parse_arm_id
from fns.models.operations import Api

API_HOSTS: Final[dict[str, str]] = {
    "arm": "management.azure.com",
    "graph": "graph.microsoft.com",
}
GRAPH_VERSIONS: Final = frozenset({"v1.0", "beta"})


class TargetError(ValueError):
    """A target or URL the gate cannot interpret. The gate turns this into a denial."""


@dataclass(frozen=True, slots=True)
class ArmTarget:
    path: ArmPath

    @classmethod
    def parse(cls, value: object) -> ArmTarget:
        try:
            return cls(parse_arm_id(value))
        except ArmIdError as exc:
            raise TargetError(str(exc)) from exc

    def __str__(self) -> str:
        return self.path.format()


@dataclass(frozen=True, slots=True)
class DirectoryTarget:
    """The Entra directory of the pinned tenant, optionally one object in it."""

    object_id: uuid.UUID | None = None

    def __str__(self) -> str:
        return "directory" if self.object_id is None else f"directory/{self.object_id}"


Target = ArmTarget | DirectoryTarget


def _split(url: str) -> tuple[str, list[str]]:
    if not isinstance(url, str) or not url.isascii() or any(c.isspace() for c in url):
        raise TargetError("URL must be an ASCII string without whitespace")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise TargetError("URL must use https")
    if parts.username or parts.password or parts.port not in (None, 443):
        raise TargetError("URL must not carry credentials or a non-default port")
    if parts.fragment:
        raise TargetError("URL must not have a fragment")
    host = (parts.hostname or "").lower()
    path = parts.path
    if not path.startswith("/") or "%" in path or "\\" in path:
        raise TargetError("URL path must be absolute and unencoded")
    segs = path[1:].split("/")
    if path != "/" and any(s in {"", ".", ".."} for s in segs):
        raise TargetError("URL path has empty or dot segments")
    return host, [s.lower() for s in segs]


def check_url(api: Api, url: str, target: Target) -> None:
    """Raise :class:`TargetError` unless ``url`` is a plausible request for ``target``."""
    host, segs = _split(url)
    if host != API_HOSTS[api]:
        raise TargetError(f"host {host!r} is not the {api} endpoint {API_HOSTS[api]!r}")
    if api == "arm":
        if not isinstance(target, ArmTarget):
            raise TargetError("ARM URL for a non-ARM target")
        target_segs = str(target)[1:].split("/")
        if segs[: len(target_segs)] != target_segs:
            raise TargetError("ARM URL path is not under the target")
    else:
        if not isinstance(target, DirectoryTarget):
            raise TargetError("Graph URL for a non-directory target")
        if not segs or segs[0] not in GRAPH_VERSIONS or len(segs) < 2:
            raise TargetError("Graph URL must start with /v1.0/ or /beta/")


def check_next_link(first_url: str, next_url: str) -> None:
    """A page link may only change the query string of the first request."""
    first_host, first_segs = _split(first_url)
    next_host, next_segs = _split(next_url)
    if (first_host, first_segs) != (next_host, next_segs):
        raise TargetError("nextLink changes host or path of the original request")
