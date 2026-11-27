"""The strike transport: writes only, lab hosts only, secrets stripped inside send()."""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from fns.adapters.azure.http import TransportError
from fns.strike.secrets import REMOVED, SecretHolder
from fns.strike.transport import HttpStrikeTransport, StrikeRequest, check_request
from tests.livekit import Canned, FakeOpener

ARM = "https://management.azure.com/subscriptions/x/listKeys?api-version=2023-05-01"
GRAPH = "https://graph.microsoft.com/v1.0/applications/x/addPassword"


class Tokens:
    def __init__(self) -> None:
        self.asked: list[str] = []

    def token(self, api: Any) -> str:
        self.asked.append(api)
        return f"FAKE-TOKEN-{api}"


@pytest.mark.parametrize(
    "request_",
    [
        StrikeRequest("arm", "GET", ARM),
        StrikeRequest("arm", "PUT", ARM),
        StrikeRequest("graph", "POST", "http://graph.microsoft.com/v1.0/x"),
        StrikeRequest("graph", "POST", "https://graph.microsoft.com.evil.example/v1.0/x"),
        StrikeRequest("graph", "POST", "https://graph.microsoft.com:8443/v1.0/x"),
        StrikeRequest("graph", "POST", "https://user:pw@graph.microsoft.com/v1.0/x"),
        StrikeRequest("graph", "POST", "https://graph.microsoft.com/v1.0/x#frag"),
        StrikeRequest("arm", "POST", GRAPH),  # Graph URL under the ARM token
        StrikeRequest("graph", "POST", ARM),
        StrikeRequest("vault", "POST", "https://kv.vault.azure.net/secrets"),  # type: ignore[arg-type]
    ],
)
def test_refused_requests(request_: StrikeRequest) -> None:
    with pytest.raises(TransportError):
        check_request(request_)


def test_refused_before_any_token_or_network() -> None:
    tokens, opener = Tokens(), FakeOpener()
    t = HttpStrikeTransport(tokens, opener=opener)
    with pytest.raises(TransportError):
        t.send(StrikeRequest("arm", "GET", ARM), SecretHolder(), "S1/list-keys")
    assert tokens.asked == [] and opener.requests == []


def test_list_keys_answer_is_stripped_inside_send() -> None:
    body = {"keys": [{"keyName": "key1", "value": "FAKE-SECRET-1", "permissions": "FULL"}]}
    opener = FakeOpener({ARM: Canned(200, body, {"x-ms-request-id": "rid-1"})})
    holder = SecretHolder()
    resp = HttpStrikeTransport(Tokens(), opener=opener).send(
        StrikeRequest("arm", "POST", ARM), holder, "S1/list-keys"
    )
    assert resp.body == {"keys": REMOVED} and resp.request_id == "rid-1"
    assert resp.secrets_removed == 1 and "FAKE-SECRET" not in repr(resp)
    assert holder.count() == 1
    sent = opener.requests[0]
    assert sent.get_method() == "POST" and sent.data is None
    assert sent.get_header("Authorization") == "Bearer FAKE-TOKEN-arm"


def test_add_password_body_and_answer() -> None:
    answer = {"keyId": "k-1", "secretText": "FAKE-SECRET-2"}
    opener = FakeOpener({GRAPH: Canned(200, answer)})
    tokens = Tokens()
    payload = {"passwordCredential": {"displayName": "fns-strike-r", "endDateTime": "x"}}
    resp = HttpStrikeTransport(tokens, opener=opener).send(
        StrikeRequest("graph", "POST", GRAPH, payload), SecretHolder(), "S3/add-password"
    )
    assert resp.body == {"keyId": "k-1", "secretText": REMOVED}
    assert tokens.asked == ["graph"]
    sent = opener.requests[0]
    assert isinstance(sent.data, bytes) and json.loads(sent.data) == payload
    assert sent.get_header("Content-type") == "application/json"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 500])
def test_error_answers_are_returned_and_stripped(status: int) -> None:
    body = {"error": {"code": "x"}, "secretText": "FAKE-SECRET-3"}
    opener = FakeOpener({GRAPH: Canned(status, body)})
    resp = HttpStrikeTransport(Tokens(), opener=opener).send(
        StrikeRequest("graph", "POST", GRAPH, {}), SecretHolder(), "k"
    )
    assert resp.status == status and not resp.ok
    assert resp.denied == (status in (401, 403))
    assert "FAKE-SECRET" not in json.dumps(resp.body)


def test_a_redirect_is_not_followed() -> None:
    opener = FakeOpener({GRAPH: Canned(302, {}, {"Location": "https://evil.example/"})})
    resp = HttpStrikeTransport(Tokens(), opener=opener).send(
        StrikeRequest("graph", "POST", GRAPH, {}), SecretHolder(), "k"
    )
    assert resp.status == 302 and len(opener.requests) == 1


@pytest.mark.parametrize("raw", [b"", b"not json", b"[1, 2]"])
def test_odd_bodies(raw: bytes) -> None:
    opener = FakeOpener({GRAPH: Canned(204, raw=raw)})
    resp = HttpStrikeTransport(Tokens(), opener=opener).send(
        StrikeRequest("graph", "POST", GRAPH, {}), SecretHolder(), "k"
    )
    assert resp.status == 204 and resp.body == {}


def test_network_error_is_a_transport_error() -> None:
    opener = FakeOpener({GRAPH: Canned(error=urllib.error.URLError("down"))})
    with pytest.raises(TransportError, match="network"):
        HttpStrikeTransport(Tokens(), opener=opener).send(
            StrikeRequest("graph", "POST", GRAPH, {}), SecretHolder(), "k"
        )
