"""Read-only HTTPS transport against a fake opener (no network)."""

from __future__ import annotations

import http.client
import urllib.error
import urllib.request
from datetime import UTC, datetime

import pytest

from fns.adapters.azure import arm, graph
from fns.adapters.azure.http import ApiRequest, TransportError
from fns.adapters.azure.live import (
    MAX_BODY_BYTES,
    USER_AGENT,
    HttpTransport,
    _NoRedirect,
    default_opener,
    parse_retry_after,
)
from fns.scope.credentials import PinnedTokens
from fns.scope.targets import DirectoryTarget
from tests.factories import SUB, TENANT
from tests.livekit import Canned, FakeCredential, FakeOpener

ARM_REQ = arm.role_assignments_request(SUB)
GRAPH_REQ = graph.service_principals_request()


def _transport(opener: FakeOpener) -> HttpTransport:
    tokens = PinnedTokens(TENANT, FakeCredential({"arm": TENANT, "graph": TENANT}))
    return HttpTransport(tokens, opener=opener)


def test_sends_get_with_bearer_token_for_the_right_api() -> None:
    opener = FakeOpener(
        default=Canned(body={"value": [{"id": "x"}]}, headers={"x-ms-request-id": "r1"})
    )
    resp = _transport(opener).fetch(ARM_REQ)
    assert resp.status == 200
    assert resp.body == {"value": [{"id": "x"}]}
    assert resp.request_id == "r1"
    (req,) = opener.requests
    assert req.get_method() == "GET"
    assert req.get_header("Authorization", "").startswith("Bearer ")
    assert req.get_header("User-agent") == USER_AGENT
    _transport(opener).fetch(GRAPH_REQ)
    arm_token = opener.requests[0].get_header("Authorization")
    graph_token = opener.requests[1].get_header("Authorization")
    assert arm_token != graph_token


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE"])
def test_refuses_anything_but_get(method: str) -> None:
    opener = FakeOpener(default=Canned())
    req = ApiRequest(
        api="graph",
        operation="graph:GET /servicePrincipals",
        target=DirectoryTarget(),
        url=GRAPH_REQ.url,
        method=method,  # type: ignore[arg-type]  # forged: the type only allows GET
    )
    with pytest.raises(TransportError, match="read-only"):
        _transport(opener).fetch(req)
    assert opener.requests == []


@pytest.mark.parametrize(
    "url",
    [
        "https://graph.microsoft.com/v1.0/servicePrincipals",  # graph host for an arm request
        "http://management.azure.com/subscriptions",
        "https://management.azure.com:8443/subscriptions",
        "https://user:pw@management.azure.com/subscriptions",
        "https://management.azure.com.evil.example/subscriptions",
    ],
)
def test_refuses_hosts_outside_the_api_allowlist(url: str) -> None:
    opener = FakeOpener(default=Canned())
    req = ApiRequest(api="arm", operation=ARM_REQ.operation, target=ARM_REQ.target, url=url)
    with pytest.raises(TransportError):
        _transport(opener).fetch(req)
    assert opener.requests == []


def test_http_errors_become_responses_with_retry_after() -> None:
    opener = FakeOpener(
        default=Canned(
            status=429,
            body={"error": {"code": "TooManyRequests"}},
            headers={"Retry-After": "7", "request-id": "g1"},
        )
    )
    resp = _transport(opener).fetch(GRAPH_REQ)
    assert (resp.status, resp.retry_after, resp.request_id) == (429, 7.0, "g1")
    assert resp.body["error"]["code"] == "TooManyRequests"


def test_error_with_non_json_body_keeps_status() -> None:
    resp = _transport(FakeOpener(default=Canned(status=502, raw=b"<html>bad gateway"))).fetch(
        ARM_REQ
    )
    assert (resp.status, resp.body) == (502, {})


@pytest.mark.parametrize("raw", [b"<html>", b"[1, 2]", b"\xff\xfe"])
def test_success_with_non_object_body_is_a_transport_error(raw: bytes) -> None:
    with pytest.raises(TransportError):
        _transport(FakeOpener(default=Canned(raw=raw))).fetch(ARM_REQ)


def test_oversized_body_is_rejected() -> None:
    big = b'{"value": "' + b"x" * MAX_BODY_BYTES + b'"}'
    with pytest.raises(TransportError, match="size"):
        _transport(FakeOpener(default=Canned(raw=big))).fetch(ARM_REQ)


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError("dns"),
        TimeoutError(),
        ConnectionResetError(),
        OSError("tls"),
        http.client.IncompleteRead(b""),
    ],
)
def test_network_errors_become_transport_errors(error: Exception) -> None:
    with pytest.raises(TransportError, match="network"):
        _transport(FakeOpener(default=Canned(error=error))).fetch(ARM_REQ)


def test_redirects_are_never_followed() -> None:
    handler = _NoRedirect()
    req = urllib.request.Request("https://management.azure.com/x")
    assert handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/") is None
    opener = default_opener()
    assert any(isinstance(h, _NoRedirect) for h in opener.handlers)  # type: ignore[attr-defined]


def test_redirect_response_is_reported_as_its_status() -> None:
    opener = FakeOpener(
        default=Canned(status=302, raw=b"", headers={"Location": "https://evil.example"})
    )
    resp = _transport(opener).fetch(ARM_REQ)
    assert resp.status == 302
    assert not resp.ok
    assert len(opener.requests) == 1


def test_parse_retry_after() -> None:
    now = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
    assert parse_retry_after("120") == 120.0
    assert parse_retry_after("Wed, 25 Nov 2026 12:00:30 GMT", now=now) == 30.0
    assert parse_retry_after("Wed, 25 Nov 2026 11:00:00 GMT", now=now) == 0.0
    assert parse_retry_after("soon") is None
    assert parse_retry_after(None) is None
    assert parse_retry_after("-5") is None


@pytest.mark.parametrize("api", ["kv", "blob"])
def test_refuses_data_plane_requests(api: str) -> None:
    """The ARM/Graph transport never carries a data-plane request (M3 P5.1)."""
    opener = FakeOpener(default=Canned())
    req = ApiRequest(
        api=api,  # type: ignore[arg-type]
        operation="kv:GET /secrets",
        target=ARM_REQ.target,
        url="https://kv.vault.azure.net/secrets?api-version=7.4",
    )
    with pytest.raises(TransportError, match="ARM and Graph only"):
        _transport(opener).fetch(req)
    assert opener.requests == []
