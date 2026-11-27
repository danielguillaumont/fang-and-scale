"""Fixture sets: on-disk format and the replaying transport.

A fixture set is a directory (or package resource) with:

    manifest.json   {"format": 1, "name", "label": "FIXTURE", "recorded_at", "tenant_id",
                     "description"}
    exchanges.json  [{"request": "GET <url>", "response": {"status", "body",
                     "request_id", "retry_after"}}, ...]
    scope.yaml      the scope manifest the set was recorded (or written) under

Requests are matched on method + canonical URL. Repeated requests consume
recorded responses in order (e.g. a 429 followed by a 200). A request with no
recorded response raises :class:`FixtureMissError`; replay never invents an
empty result.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Any, Final

from fns.adapters.azure.http import ApiRequest, ApiResponse, canonical_url
from fns.inputcap import MAX_JSON_BYTES, MAX_RECORD_BYTES, read_capped, read_capped_text
from fns.models.base import FnsModel
from fns.models.ids import TzDatetime
from fns.yamlio import MAX_BYTES as YAML_MAX_BYTES

FIXTURE_LABEL: Final = "FIXTURE"
FORMAT: Final = 1


class FixtureError(RuntimeError):
    pass


class FixtureMissError(FixtureError):
    def __init__(self, key: str) -> None:
        super().__init__(f"no recorded response for {key}")
        self.key = key


class FixtureManifest(FnsModel):
    format: int
    name: str
    label: str
    recorded_at: TzDatetime
    tenant_id: str
    description: str = ""


def request_key(method: str, url: str) -> str:
    return f"{method.upper()} {canonical_url(url)}"


@dataclass(frozen=True)
class FixtureSet:
    manifest: FixtureManifest
    exchanges: tuple[tuple[str, ApiResponse], ...]
    scope_yaml: str

    @property
    def recorded_at(self) -> datetime:
        return self.manifest.recorded_at

    @classmethod
    def load(cls, root: Traversable) -> FixtureSet:
        manifest = FixtureManifest.model_validate_json(
            read_capped(root.joinpath("manifest.json"), MAX_RECORD_BYTES)
        )
        if manifest.format != FORMAT or manifest.label != FIXTURE_LABEL:
            raise FixtureError("unsupported fixture format or missing FIXTURE label")
        raw: list[dict[str, Any]] = json.loads(
            read_capped(root.joinpath("exchanges.json"), MAX_JSON_BYTES)
        )
        exchanges = []
        for ex in raw:
            method, _, url = str(ex["request"]).partition(" ")
            r = ex["response"]
            exchanges.append(
                (
                    request_key(method, url),
                    ApiResponse(
                        status=int(r["status"]),
                        body=dict(r.get("body") or {}),
                        request_id=r.get("request_id"),
                        retry_after=r.get("retry_after"),
                    ),
                )
            )
        return cls(
            manifest,
            tuple(exchanges),
            read_capped_text(root.joinpath("scope.yaml"), YAML_MAX_BYTES),
        )


def bundled(name: str) -> Traversable:
    """A fixture set shipped inside the package (works after pip install)."""
    root = files("fns.fixtures").joinpath("data", name)
    if not root.joinpath("manifest.json").is_file():
        raise FixtureError(f"no bundled fixture set {name!r}")
    return root


class FixtureTransport:
    """Replays a :class:`FixtureSet`. Never touches the network."""

    def __init__(self, fixture: FixtureSet) -> None:
        self._queues: dict[str, deque[ApiResponse]] = defaultdict(deque)
        for key, resp in fixture.exchanges:
            self._queues[key].append(resp)
        self.served: list[str] = []

    def fetch(self, request: ApiRequest) -> ApiResponse:
        key = request_key(request.method, request.url)
        queue = self._queues.get(key)
        if not queue:
            raise FixtureMissError(key)
        self.served.append(key)
        return queue.popleft()

    def unused(self) -> list[str]:
        return sorted(k for k, q in self._queues.items() for _ in q)
