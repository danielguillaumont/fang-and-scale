"""Data-plane HTTPS transport for ``fns prove`` (Key Vault ``GET``, blob ``HEAD``).

Defence in depth behind the scope gate, which has already approved the exact URL.

**Nothing from a response body survives this module (decision V6).**
:class:`DataResponse` has no body field, so no caller can store one:

- a ``2xx`` body is never read: the response is closed unread. For a secret that
  is the secret value, so it never reaches memory that this code controls;
- for ``401`` and ``403`` from Key Vault, at most :data:`MAX_ERROR_BYTES` of the
  error body are read to find ``error.code`` and ``error.innerError.code``. Only
  codes on :data:`KNOWN_CODES` are kept; anything else becomes ``"unrecognized"``.
  The message text is discarded. An authorization error body never holds a
  secret value;
- every other status is closed unread;
- only the headers in :data:`KEPT_HEADERS` are read;
- exceptions carry the exception type only, never response content.

Other limits: ``GET`` only for ``kv``, ``HEAD`` only for ``blob``; the host must be
the API's data-plane suffix; redirects are never followed (the bearer token would
go with them); shared keys and SAS are never sent.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from email.message import Message
from typing import IO, Final, Literal
from urllib.parse import urlsplit

from fns.adapters.azure.http import TransportError
from fns.adapters.azure.live import TIMEOUT_SECONDS, USER_AGENT, Opener, default_opener
from fns.models.operations import parse_operation
from fns.scope.credentials import TokenProvider
from fns.scope.targets import DATA_HOST_SUFFIXES, ArmTarget

DataApi = Literal["kv", "blob"]
METHODS: Final[dict[str, str]] = {"kv": "GET", "blob": "HEAD"}
STORAGE_VERSION: Final = "2023-11-03"
"""``x-ms-version`` for blob requests (bearer tokens need 2017-11-09 or later)."""
MAX_ERROR_BYTES: Final = 8 * 1024
KEPT_HEADERS: Final = ("x-ms-request-id", "x-ms-error-code")
KNOWN_CODES: Final = frozenset(
    {
        # Key Vault error.code / error.innerError.code
        "Forbidden",
        "ForbiddenByRbac",
        "AccessDenied",
        "ForbiddenByFirewall",
        "ForbiddenByPolicy",
        "Unauthorized",
        "AKV10032",
        "SecretNotFound",
        "BadParameter",
        "Throttled",
        # Storage x-ms-error-code
        "AuthorizationPermissionMismatch",
        "AuthorizationFailure",
        "AuthorizationSourceIPMismatch",
        "AuthorizationProtocolMismatch",
        "NoAuthenticationInformation",
        "InvalidAuthenticationInfo",
        "BlobNotFound",
        "ContainerNotFound",
        "ServerBusy",
    }
)


@dataclass(frozen=True, slots=True)
class DataRequest:
    api: DataApi
    operation: str
    target: ArmTarget
    url: str

    @property
    def method(self) -> str:
        return METHODS[self.api]


@dataclass(frozen=True, slots=True)
class DataResponse:
    """Status and allowlisted metadata only. There is deliberately no body."""

    status: int
    request_id: str | None = None
    error_code: str | None = None
    inner_code: str | None = None
    duration_ms: int = 0


def _code(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value if value in KNOWN_CODES else "unrecognized"


def _kv_error_codes(stream: IO[bytes]) -> tuple[str | None, str | None]:
    try:
        parsed = json.loads(stream.read(MAX_ERROR_BYTES))
    except (OSError, http.client.HTTPException, ValueError):
        return None, None
    err = parsed.get("error") if isinstance(parsed, dict) else None
    if not isinstance(err, dict):
        return None, None
    inner = err.get("innerError") or err.get("innererror")
    return _code(err.get("code")), _code(inner.get("code") if isinstance(inner, dict) else None)


class DataPlaneTransport:
    def __init__(
        self,
        tokens: TokenProvider,
        *,
        opener: Opener | None = None,
        timeout: float = TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.tokens = tokens
        self.opener = opener or default_opener()
        self.timeout = timeout
        self.clock = clock

    def fetch(self, request: DataRequest) -> DataResponse:
        op = parse_operation(request.operation)
        if op.api != request.api or op.api not in METHODS:
            raise TransportError("operation does not match the data-plane API")
        method = METHODS[request.api]
        parts = urlsplit(request.url)
        suffix = DATA_HOST_SUFFIXES[request.api]
        if parts.scheme != "https" or not (parts.hostname or "").endswith(suffix):
            raise TransportError(f"refusing to send a {request.api} request off its endpoint")
        if parts.port is not None or parts.username or parts.password:
            raise TransportError("refusing a URL with a port or credentials")
        headers = {
            "Authorization": f"Bearer {self.tokens.token(request.api)}",
            "User-Agent": USER_AGENT,
        }
        if request.api == "blob":
            headers["x-ms-version"] = STORAGE_VERSION
        else:
            headers["Accept"] = "application/json"
        req = urllib.request.Request(  # noqa: S310 - scheme and host checked above
            request.url, method=method, headers=headers
        )
        started = self.clock()
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                # A success body is never read; leaving the context closes it unread.
                return self._response(int(resp.status), resp.headers, None, request.api, started)
        except urllib.error.HTTPError as err:
            try:
                return self._response(err.code, err.headers, err, request.api, started)
            finally:
                err.close()
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(f"{type(exc).__name__}: network error") from None

    def _response(
        self,
        status: int,
        headers: Message,
        error_stream: IO[bytes] | None,
        api: str,
        started: float,
    ) -> DataResponse:
        error_code = _code(headers.get("x-ms-error-code"))
        inner = None
        if api == "kv" and status in (401, 403) and error_stream is not None:
            error_code, inner = _kv_error_codes(error_stream)
        request_id = headers.get("x-ms-request-id") or None
        return DataResponse(
            status=status,
            request_id=request_id if isinstance(request_id, str) else None,
            error_code=error_code,
            inner_code=inner,
            duration_ms=max(0, int((self.clock() - started) * 1000)),
        )
