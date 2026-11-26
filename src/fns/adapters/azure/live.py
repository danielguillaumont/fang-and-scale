"""Live HTTPS transport for ARM and Microsoft Graph (stdlib only).

Defense in depth behind the scope gate, which has already approved the URL:

- GET only: there is no code path here that can send a write;
- host allowlist per API, https only, port 443;
- redirects are never followed. urllib's default handler would replay the
  request, bearer token included, to whatever host a ``Location`` names;
- responses are capped at ``MAX_BODY_BYTES`` and must be a JSON object;
- network errors become :class:`TransportError`; HTTP errors become a normal
  :class:`ApiResponse` with their status, so the collector records coverage.
"""

from __future__ import annotations

import email.utils
import http.client
import json
import ssl
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.message import Message
from typing import IO, Any, Final, Protocol
from urllib.parse import urlsplit

from fns import __version__
from fns.adapters.azure.http import ApiRequest, ApiResponse, TransportError
from fns.scope.credentials import TokenProvider
from fns.scope.targets import API_HOSTS

MAX_BODY_BYTES: Final = 32 * 1024 * 1024
TIMEOUT_SECONDS: Final = 30.0
USER_AGENT: Final = f"fang-and-scale/{__version__}"
REQUEST_ID_HEADERS: Final = ("x-ms-request-id", "request-id", "client-request-id")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> urllib.request.Request | None:
        return None  # urllib then surfaces the 3xx as an HTTPError


class Opener(Protocol):
    def open(
        self, fullurl: urllib.request.Request, data: None = None, timeout: float | None = None
    ) -> Any: ...


def default_opener() -> Opener:
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Seconds to wait: ``Retry-After`` is either delta-seconds or an HTTP date."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return max(0.0, (when - (now or datetime.now(UTC))).total_seconds())


def _check_url(request: ApiRequest) -> None:
    parts = urlsplit(request.url)
    if parts.scheme != "https" or parts.hostname != API_HOSTS[request.api]:
        raise TransportError(f"refusing to send a {request.api} request to {parts.hostname!r}")
    if parts.port not in (None, 443) or parts.username or parts.password:
        raise TransportError("refusing a URL with a port or credentials")


class HttpTransport:
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

    def fetch(self, request: ApiRequest) -> ApiResponse:
        if request.method != "GET":
            raise TransportError(f"read-only transport refuses {request.method}")
        _check_url(request)
        req = urllib.request.Request(  # noqa: S310 - scheme and host checked above
            request.url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self.tokens.token(request.api)}",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return self._response(resp.status, resp.headers, resp)
        except urllib.error.HTTPError as err:
            try:
                return self._response(err.code, err.headers, err)
            finally:
                err.close()
        # URLError, TimeoutError, SSLError and ConnectionError are all OSError;
        # IncompleteRead and friends are HTTPException.
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(f"{type(exc).__name__}: network error") from exc

    def _response(self, status: int, headers: Message, stream: IO[bytes]) -> ApiResponse:
        raw = stream.read(MAX_BODY_BYTES + 1)
        if len(raw) > MAX_BODY_BYTES:
            raise TransportError("response body exceeds the size limit")
        body: dict[str, Any] = {}
        if raw.strip():
            try:
                parsed = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                if 200 <= status < 300:
                    raise TransportError("response is not JSON") from exc
                parsed = {}
            if isinstance(parsed, dict):
                body = parsed
            elif 200 <= status < 300:
                raise TransportError("response JSON is not an object")
        request_id = next((headers[h] for h in REQUEST_ID_HEADERS if headers.get(h)), None)
        return ApiResponse(
            status=status,
            body=body,
            request_id=request_id,
            retry_after=parse_retry_after(headers.get("Retry-After")),
        )
