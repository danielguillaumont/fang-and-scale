from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from fns.adapters.azure.http import ApiRequest, ApiResponse
from fns.fixtures.recorder import IDMAP_FILE, Recorder
from fns.fixtures.replay import (
    FixtureError,
    FixtureMissError,
    FixtureSet,
    FixtureTransport,
    bundled,
    request_key,
)
from fns.fixtures.sanitize import PLACEHOLDER_RE
from fns.scope.targets import DirectoryTarget

REAL_TENANT = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
REAL_SP = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
AT = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def _req(url: str) -> ApiRequest:
    return ApiRequest(
        api="graph", operation="graph:GET /servicePrincipals", target=DirectoryTarget(), url=url
    )


class FakeLive:
    def __init__(self, responses: dict[str, list[ApiResponse]]) -> None:
        self.responses = responses

    def fetch(self, request: ApiRequest) -> ApiResponse:
        return self.responses[request.url].pop(0)


def test_request_key_is_case_and_query_order_insensitive() -> None:
    a = request_key("get", "https://Graph.Microsoft.com/v1.0/servicePrincipals?b=2&a=1")
    b = request_key("GET", "https://graph.microsoft.com/v1.0/serviceprincipals?a=1&b=2")
    assert a == b


def test_record_then_replay_round_trip(tmp_path: Path) -> None:
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{REAL_SP}/owners"
    live = FakeLive(
        {
            url: [
                ApiResponse(429, {"error": {"code": "TooManyRequests"}}, "req-1", 2.0),
                ApiResponse(
                    200, {"value": [{"id": REAL_SP, "mail": "a@contoso.com"}]}, "req-2", None
                ),
            ]
        }
    )
    rec = Recorder(live, tmp_path / "set", name="t", tenant_id=REAL_TENANT, recorded_at=AT)
    assert rec.fetch(_req(url)).status == 429
    real = rec.fetch(_req(url))
    assert real.body["value"][0]["id"] == REAL_SP  # the caller still sees the real response
    rec.finalize(f"tenant_id: {REAL_TENANT}\n")

    out = tmp_path / "set"
    written = "".join(
        (out / n).read_text(encoding="utf-8")
        for n in ("exchanges.json", "manifest.json", "scope.yaml")
    )
    assert REAL_SP not in written
    assert REAL_TENANT not in written
    assert "contoso" not in written
    assert "req-1" not in written  # request IDs are not kept
    assert (out / IDMAP_FILE).is_file()

    fixture = FixtureSet.load(out)
    assert PLACEHOLDER_RE.match(fixture.manifest.tenant_id)
    sanitized_url = json.loads((out / "exchanges.json").read_text(encoding="utf-8"))[0][
        "request"
    ].split(" ", 1)[1]
    transport = FixtureTransport(fixture)
    first = transport.fetch(_req(sanitized_url))
    second = transport.fetch(_req(sanitized_url))
    assert (first.status, first.retry_after) == (429, 2.0)
    assert second.status == 200
    assert transport.unused() == []
    with pytest.raises(FixtureMissError):
        transport.fetch(_req(sanitized_url))


def test_rerecording_reuses_the_idmap(tmp_path: Path) -> None:
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{REAL_SP}"
    outs: list[Any] = []
    for _ in range(2):
        live = FakeLive({url: [ApiResponse(200, {"id": REAL_SP}, None, None)]})
        rec = Recorder(live, tmp_path / "set", name="t", tenant_id=REAL_TENANT, recorded_at=AT)
        rec.fetch(_req(url))
        rec.finalize("")
        outs.append(json.loads((tmp_path / "set" / "exchanges.json").read_text(encoding="utf-8")))
    assert outs[0] == outs[1]


def test_unknown_request_raises_instead_of_returning_empty() -> None:
    fixture = FixtureSet.load(bundled("demo-scout"))
    with pytest.raises(FixtureMissError, match="no recorded response"):
        FixtureTransport(fixture).fetch(_req("https://graph.microsoft.com/v1.0/users"))


def test_bundled_rejects_unknown_set() -> None:
    with pytest.raises(FixtureError):
        bundled("no-such-set")


def test_fixture_without_label_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "format": 1,
                "name": "x",
                "label": "LIVE",
                "recorded_at": "2026-11-25T12:00:00Z",
                "tenant_id": "t",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "exchanges.json").write_text("[]", encoding="utf-8")
    (tmp_path / "scope.yaml").write_text("", encoding="utf-8")
    with pytest.raises(FixtureError, match="FIXTURE"):
        FixtureSet.load(tmp_path)
