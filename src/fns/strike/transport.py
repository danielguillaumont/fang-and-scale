"""The strike transport: sends one gated write, and strips secrets from the answer.

Defense in depth behind the write gate, which has already approved the request:

- methods ``POST``, ``PATCH`` and ``DELETE`` only, to the ARM and Graph hosts only,
  https on port 443;
- redirects are never followed (the bearer token would go with them);
- the response's secret fields are removed by :func:`fns.strike.secrets.strip_secrets`
  inside :meth:`StrikeTransport.send`, before a :class:`StrikeResponse` exists,
  so no other code ever holds them. Removed values go to the run's
  :class:`~fns.strike.secrets.SecretHolder`.

Subclasses implement :meth:`StrikeTransport._exchange`: the live HTTPS transport
here, and the fake tenant in the tests.

S4's token request has its own :class:`TokenTransport`: ``POST`` to
``login.microsoftonline.com`` only, form-encoded, no bearer token, no redirects. The
client secret is added to the form inside :meth:`TokenTransport.send_token` and the
``access_token`` is stripped from the answer before anything else sees it.
"""

from __future__ import annotations

import http.client
import json
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal
from urllib.parse import urlencode, urlsplit

from fns.adapters.azure.http import TransportError
from fns.adapters.azure.live import (
    MAX_BODY_BYTES,
    REQUEST_ID_HEADERS,
    TIMEOUT_SECONDS,
    USER_AGENT,
    Opener,
    default_opener,
)
from fns.scope.credentials import TokenProvider
from fns.scope.writes import TOKEN_HOST
from fns.strike.secrets import SecretHolder, strip_secrets

WriteApi = Literal["arm", "graph"]
HOSTS: Final[dict[WriteApi, str]] = {"arm": "management.azure.com", "graph": "graph.microsoft.com"}
WRITE_METHODS: Final = frozenset({"POST", "PATCH", "DELETE"})


@dataclass(frozen=True, slots=True)
class StrikeRequest:
    api: WriteApi
    method: str
    url: str
    body: object = None


@dataclass(frozen=True, slots=True)
class StrikeResponse:
    status: int
    body: dict[str, Any]
    """The JSON body with every secret field replaced (``strip_secrets``)."""
    request_id: str | None = None
    secrets_removed: int = 0

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def denied(self) -> bool:
        return self.status in (401, 403)


def check_request(request: StrikeRequest) -> None:
    if request.method not in WRITE_METHODS:
        raise TransportError(f"the strike transport sends writes only, not {request.method}")
    host = HOSTS.get(request.api)
    parts = urlsplit(request.url)
    if host is None or parts.scheme != "https" or parts.hostname != host:
        raise TransportError(f"refusing to send a strike write to {parts.hostname!r}")
    if parts.port not in (None, 443) or parts.username or parts.password or parts.fragment:
        raise TransportError("refusing a URL with a port, credentials or a fragment")


class StrikeTransport(ABC):
    """Base class: :meth:`send` is the only entry point, and it strips secrets."""

    def send(self, request: StrikeRequest, holder: SecretHolder, step: str) -> StrikeResponse:
        check_request(request)
        status, raw, request_id = self._exchange(request)
        clean, found = strip_secrets(raw)
        holder.put(step, found)
        del raw, found
        if not isinstance(clean, dict):
            clean = {}
        return StrikeResponse(status, clean, request_id, holder.count_for(step))

    @abstractmethod
    def _exchange(self, request: StrikeRequest) -> tuple[int, object, str | None]:
        """Send it; return ``(status, raw JSON body, request id)``."""


class HttpStrikeTransport(StrikeTransport):
    """Live HTTPS writes, with tokens from one pinned identity (the agent)."""

    def __init__(
        self,
        tokens: TokenProvider,
        *,
        opener: Opener | None = None,
        timeout: float = TIMEOUT_SECONDS,
    ) -> None:
        self.tokens = tokens
        self.opener = opener or default_opener()
        self.timeout = timeout

    def _exchange(self, request: StrikeRequest) -> tuple[int, object, str | None]:
        data = None if request.body is None else json.dumps(request.body).encode()
        headers = {
            "Authorization": f"Bearer {self.tokens.token(request.api)}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(  # noqa: S310 - scheme and host checked in send()
            request.url, data=data, method=request.method, headers=headers
        )
        return _open(self.opener, req, self.timeout)


def _open(
    opener: Opener, req: urllib.request.Request, timeout: float
) -> tuple[int, object, str | None]:
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _read(resp.status, resp.headers, resp)
    except urllib.error.HTTPError as err:
        try:
            return _read(err.code, err.headers, err)
        finally:
            err.close()
    except (OSError, http.client.HTTPException) as exc:
        raise TransportError(f"{type(exc).__name__}: network error") from exc


def _read(status: int, headers: Any, stream: Any) -> tuple[int, object, str | None]:
    raw = stream.read(MAX_BODY_BYTES + 1)
    if len(raw) > MAX_BODY_BYTES:
        raise TransportError("response body exceeds the size limit")
    body: object = {}
    if raw.strip():
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = {}
    request_id = next((headers[h] for h in REQUEST_ID_HEADERS if headers.get(h)), None)
    return status, body, request_id


# --- S4: the token request ------------------------------------------------------------

_TOKEN_PATH = re.compile(r"^/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/oauth2/v2\.0/token$")
TOKEN_FIELDS: Final = frozenset({"client_id", "grant_type", "scope"})


@dataclass(frozen=True, slots=True)
class TokenWire:
    """S4 step 1 as sent, minus the secret: the gate approved exactly these fields."""

    url: str
    form: Mapping[str, str] = field(default_factory=dict)


def check_token_wire(wire: TokenWire) -> None:
    parts = urlsplit(wire.url)
    if parts.scheme != "https" or parts.hostname != TOKEN_HOST:
        raise TransportError(f"refusing to send a token request to {parts.hostname!r}")
    if parts.port not in (None, 443) or parts.username or parts.password:
        raise TransportError("refusing a token URL with a port or credentials")
    if parts.query or parts.fragment or "#" in wire.url or not _TOKEN_PATH.fullmatch(parts.path):
        raise TransportError("the token URL is /<tenant>/oauth2/v2.0/token and nothing else")
    if set(wire.form) != TOKEN_FIELDS or not all(isinstance(v, str) for v in wire.form.values()):
        raise TransportError(f"the token form is exactly {sorted(TOKEN_FIELDS)} plus the secret")


class TokenTransport(ABC):
    """Base class: :meth:`send_token` adds the secret and strips the token."""

    def send_token(
        self, wire: TokenWire, secret: str, holder: SecretHolder, step: str
    ) -> StrikeResponse:
        check_token_wire(wire)
        if not isinstance(secret, str) or not secret:
            raise TransportError("no client secret to send")
        status, raw, request_id = self._exchange_token(wire, secret)
        clean, found = strip_secrets(raw)
        holder.put(step, found)
        del raw, found, secret
        if not isinstance(clean, dict):
            clean = {}
        return StrikeResponse(status, clean, request_id, holder.count_for(step))

    @abstractmethod
    def _exchange_token(self, wire: TokenWire, secret: str) -> tuple[int, object, str | None]:
        """Send it; return ``(status, raw JSON body, request id)``."""


class HttpTokenTransport(TokenTransport):
    """The live token request: form-encoded, no bearer token, redirects refused."""

    def __init__(self, *, opener: Opener | None = None, timeout: float = TIMEOUT_SECONDS) -> None:
        self.opener = opener or default_opener()
        self.timeout = timeout

    def _exchange_token(self, wire: TokenWire, secret: str) -> tuple[int, object, str | None]:
        data = urlencode({**dict(wire.form), "client_secret": secret}).encode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        req = urllib.request.Request(  # noqa: S310 - scheme and host checked in send_token()
            wire.url, data=data, method="POST", headers=headers
        )
        del data
        return _open(self.opener, req, self.timeout)
