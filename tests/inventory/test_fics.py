"""Federated identity credentials collector (queue item 2, pending review)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from fns.adapters.azure import graph
from fns.adapters.azure.http import ApiRequest, ApiResponse
from fns.fixtures.replay import FixtureTransport
from fns.inventory.collector import FICS, FICS_COLLECTOR, NOT_COLLECTED, UAMI_FICS_NOT_READ
from fns.models.snapshot import FederatedCredential
from tests.factories import pid
from tests.inventory.test_collector import FIXTURE, GOLDEN, _manifest, run

APPS = (pid(300), pid(301), pid(302))
GH = "https://token.actions.githubusercontent.com"


def _fic(n: int, **extra: Any) -> dict[str, Any]:
    return {
        "id": pid(970 + n),
        "name": f"gh-{n}",
        "issuer": GH,
        "subject": f"repo:org/app{n}:pull_request",
        "audiences": ["api://AzureADTokenExchange"],
        "description": "free text with a person's name in it",
        **extra,
    }


class WithFics:
    def __init__(
        self, rows: dict[str, list[Any]] | None = None, status: dict[str, int] | None = None
    ) -> None:
        self.inner = FixtureTransport(FIXTURE)
        self.rows = rows or {}
        self.status = status or {}
        self.requests: list[ApiRequest] = []

    def fetch(self, request: ApiRequest) -> ApiResponse:
        self.requests.append(request)
        if request.operation == graph.OP_APP_FICS:
            app = request.url.split("/applications/")[1].split("/")[0]
            if app in self.status:
                return ApiResponse(self.status[app], {"error": {"code": "Forbidden"}}, "rid")
            return ApiResponse(200, {"value": self.rows.get(app, [])}, "rid")
        return self.inner.fetch(request)

    def unused(self) -> list[str]:
        return self.inner.unused()


def _with_fics() -> Any:
    m = _manifest()
    scout = sorted({*m.allowed_operations["scout"], graph.OP_APP_FICS})
    return _manifest(allowed_operations={**m.allowed_operations, "scout": scout})


def _reason(snap: Any) -> list[str]:
    return [n.reason for n in snap.coverage.not_collected if n.surface == FICS]


def test_a_scope_without_the_read_is_unchanged() -> None:
    r = run()
    assert r.snapshot.digest() == GOLDEN and r.snapshot.federated_credentials == ()
    (default,) = [n for n in NOT_COLLECTED if n.surface == FICS]
    assert _reason(r.snapshot) == [default.reason]
    assert graph.OP_APP_FICS not in {d.operation for d in r.journal.decisions}


def test_credentials_are_collected_for_every_application() -> None:
    t = WithFics({APPS[0]: [_fic(1), _fic(2, subject=None)]})
    r = run(t, _with_fics())
    fics = r.snapshot.federated_credentials
    assert [(f.owner, f.name, f.subject) for f in fics] == [
        (APPS[0], "gh-1", "repo:org/app1:pull_request"),
        (APPS[0], "gh-2", None),
    ]
    assert "free text" not in r.snapshot.canonical_json()
    asked = {
        q.url.split("/applications/")[1].split("/")[0]
        for q in t.requests
        if q.operation == graph.OP_APP_FICS
    }
    assert asked == set(APPS)
    assert r.collector(FICS_COLLECTOR).status == "complete"
    # Managed identities keep theirs in ARM: the surface never closes from Graph alone.
    assert _reason(r.snapshot) == [UAMI_FICS_NOT_READ]


def test_a_failed_listing_is_named() -> None:
    r = run(WithFics(status={APPS[2]: 403}), _with_fics())
    assert r.collector(FICS_COLLECTOR).status == "partial"
    (reason,) = _reason(r.snapshot)
    assert reason.startswith(f"collector {FICS_COLLECTOR} is partial; ")


def test_a_bad_row_is_counted() -> None:
    rows = [_fic(1, audiences="api://AzureADTokenExchange"), _fic(2, id="x"), _fic(3, issuer="")]
    r = run(WithFics({APPS[0]: rows}), _with_fics())
    assert r.snapshot.federated_credentials == ()
    assert "bad-item" in r.collector(FICS_COLLECTOR).error_codes


def test_the_model_sorts_audiences_and_rejects_extra_fields() -> None:
    prov = {"source_api": graph.OP_APP_FICS, "observed_at": "2026-11-28T00:00:00Z"}
    base = {"owner": APPS[0], "id": pid(970), "name": "n", "issuer": GH, "provenance": prov}
    f = FederatedCredential.model_validate({**base, "audiences": ["b", "a", "a"]})
    assert f.audiences == ("a", "b")
    with pytest.raises(ValidationError):
        FederatedCredential.model_validate({**base, "description": "x"})
    with pytest.raises(ValidationError):
        FederatedCredential.model_validate({**base, "owner": "not-a-guid"})


def test_order_does_not_change_the_digest() -> None:
    a = run(WithFics({APPS[0]: [_fic(1), _fic(2)]}), _with_fics()).snapshot
    b = run(WithFics({APPS[0]: [_fic(2), _fic(1)]}), _with_fics()).snapshot
    assert a.digest() == b.digest()
    assert json.loads(a.canonical_json())["federated_credentials"]
