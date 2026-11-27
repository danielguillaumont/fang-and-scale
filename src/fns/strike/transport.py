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
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Final, Literal
from urllib.parse import urlsplit

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
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return self._read(resp.status, resp.headers, resp)
        except urllib.error.HTTPError as err:
            try:
                return self._read(err.code, err.headers, err)
            finally:
                err.close()
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(f"{type(exc).__name__}: network error") from exc

    @staticmethod
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
