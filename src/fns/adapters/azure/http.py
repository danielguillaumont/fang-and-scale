"""Transport-level request/response types.

Collectors speak in :class:`ApiRequest` / :class:`ApiResponse`. A transport
performs one HTTP exchange per ``fetch``: the fixture replayer in Phase A, the
live Azure transport in Phase B. Paging and 429 retries are driven by the
collector so every page and every retry is its own gated, budgeted call
(SDK pagers would follow nextLink behind the gate's back).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final, Literal, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fns.models.operations import Api
from fns.scope.targets import Target

ARM_BASE: Final = "https://management.azure.com"
GRAPH_BASE: Final = "https://graph.microsoft.com/v1.0"


def canonical_url(url: str) -> str:
    """Stable key for a URL: lowercase scheme/host/path, query parameters sorted."""
    parts = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)), safe="$(),'=")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.lower(), query, ""))


@dataclass(frozen=True, slots=True)
class ApiRequest:
    api: Api
    operation: str
    """Scope operation checked by the gate (``arm:...`` or ``graph:...``)."""
    target: Target
    url: str
    method: Literal["GET"] = "GET"

    @property
    def key(self) -> str:
        return f"{self.method} {canonical_url(self.url)}"


@dataclass(frozen=True, slots=True)
class ApiResponse:
    status: int
    body: dict[str, Any] = field(default_factory=dict)
    request_id: str | None = None
    retry_after: float | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def next_link(self) -> str | None:
        link = self.body.get("nextLink") or self.body.get("@odata.nextLink")
        return link if isinstance(link, str) and link else None


class TransportError(RuntimeError):
    """A transport could not complete an exchange (network, TLS, auth)."""


class Transport(Protocol):
    def fetch(self, request: ApiRequest) -> ApiResponse: ...
