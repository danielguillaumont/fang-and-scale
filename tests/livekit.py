"""Fakes for live-path tests: tokens, credential sources and an HTTP opener.

Nothing here touches the network; ``FakeOpener`` raises on any URL it was not
given a response for.
"""

from __future__ import annotations

import base64
import io
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from typing import Any


def fake_jwt(**claims: Any) -> str:
    def b64(obj: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


@dataclass
class AccessToken:
    token: str
    expires_on: int


@dataclass
class FakeCredential:
    """Mimics azure-identity's ``get_token``; tids per scope."""

    tids: dict[str, str | None]
    expires_on: int = 10_000
    calls: list[str] = field(default_factory=list)
    error: Exception | None = None

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        (scope,) = scopes
        self.calls.append(scope)
        if self.error is not None:
            raise self.error
        api = "arm" if "management" in scope else "graph"
        tid = self.tids.get(api)
        claims = {"tid": tid} if tid else {"oid": "x"}
        return AccessToken(fake_jwt(**claims, scp=api), self.expires_on)


class _Resp(io.BytesIO):
    def __init__(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        super().__init__(body)
        self.status = status
        self.headers = Message()
        for k, v in headers.items():
            self.headers[k] = v


@dataclass
class Canned:
    status: int = 200
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    raw: bytes | None = None
    error: Exception | None = None

    def payload(self) -> bytes:
        if self.raw is not None:
            return self.raw
        return json.dumps(self.body if self.body is not None else {"value": []}).encode()


@dataclass
class FakeOpener:
    responses: dict[str, Canned] = field(default_factory=dict)
    requests: list[urllib.request.Request] = field(default_factory=list)
    default: Canned | None = None

    def open(
        self, fullurl: urllib.request.Request, data: None = None, timeout: float | None = None
    ) -> Any:
        self.requests.append(fullurl)
        canned = self.responses.get(fullurl.full_url, self.default)
        if canned is None:
            raise AssertionError(f"unexpected request {fullurl.full_url}")
        if canned.error is not None:
            raise canned.error
        payload = canned.payload()
        if canned.status >= 300:
            hdrs = Message()
            for k, v in canned.headers.items():
                hdrs[k] = v
            raise urllib.error.HTTPError(
                fullurl.full_url, canned.status, "error", hdrs, io.BytesIO(payload)
            )
        return _Resp(canned.status, payload, canned.headers)
