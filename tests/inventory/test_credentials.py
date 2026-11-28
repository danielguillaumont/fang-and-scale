"""Key/password credential metadata (queue item 1, 2026-11-28, pending review).

Optional per-object reads: a scope that does not list them collects exactly what
it did before, and no value (key, thumbprint, hint, secretText) ever reaches the
snapshot.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from fns.adapters.azure import graph
from fns.adapters.azure.http import ApiRequest, ApiResponse
from fns.fixtures.replay import FixtureTransport
from fns.fixtures.sanitize import REDACTED, IdMap, sanitize
from fns.inventory.collector import APP_CREDENTIALS, CREDENTIALS_COLLECTOR, NOT_COLLECTED
from fns.models.snapshot import Credential, Snapshot
from tests.factories import pid
from tests.inventory.test_collector import FIXTURE, GOLDEN, _manifest, run

APPS = (pid(300), pid(301), pid(302))
TENANT_SPS = (pid(100), pid(101), pid(104), pid(105))
GRAPH_SP = pid(103)  # Microsoft Graph: another tenant's application

SECRETS = ("MIIC-PUBLIC-CERT-BYTES", "ABCDEF0123456789THUMB", "Xy~", "s3cr3t-text-value")


def _key(n: int, **extra: Any) -> dict[str, Any]:
    return {
        "keyId": pid(900 + n),
        "displayName": f"cert-{n}",
        "type": "AsymmetricX509Cert",
        "usage": "Verify",
        "startDateTime": "2026-01-01T00:00:00Z",
        "endDateTime": "2027-01-01T00:00:00.1234567Z",
        "key": SECRETS[0],
        "customKeyIdentifier": SECRETS[1],
        **extra,
    }


def _password(n: int, **extra: Any) -> dict[str, Any]:
    return {
        "keyId": pid(950 + n),
        "displayName": f"secret-{n}",
        "startDateTime": "2026-02-01T00:00:00Z",
        "endDateTime": "2026-08-01T00:00:00Z",
        "hint": SECRETS[2],
        "secretText": SECRETS[3],
        **extra,
    }


def _body(oid: str, keys: list[Any] | None = None, pws: list[Any] | None = None) -> dict[str, Any]:
    return {"id": oid, "keyCredentials": keys or [], "passwordCredentials": pws or []}


class WithCredentials:
    """The demo recording plus per-object credential reads."""

    def __init__(
        self,
        bodies: dict[str, dict[str, Any]] | None = None,
        status: dict[str, int] | None = None,
        drop_sp: str | None = None,
    ) -> None:
        self.inner = FixtureTransport(FIXTURE)
        self.bodies = bodies or {}
        self.status = status or {}
        self.drop_sp = drop_sp
        self.requests: list[ApiRequest] = []

    def fetch(self, request: ApiRequest) -> ApiResponse:
        self.requests.append(request)
        if request.operation in graph.CREDENTIAL_OPERATIONS:
            oid = request.url.split("?")[0].rsplit("/", 1)[-1]
            if oid in self.status:
                return ApiResponse(self.status[oid], {"error": {"code": "Forbidden"}}, "rid")
            return ApiResponse(200, self.bodies.get(oid, _body(oid)), "rid")
        resp = self.inner.fetch(request)
        if self.drop_sp and request.operation == graph.OP_SERVICE_PRINCIPALS:
            rows = [r for r in resp.body["value"] if r.get("id") != self.drop_sp]
            return ApiResponse(resp.status, {**resp.body, "value": rows}, resp.request_id)
        return resp

    def unused(self) -> list[str]:
        return self.inner.unused()


def _with_ops(*ops: str) -> Any:
    m = _manifest()
    scout = sorted({*m.allowed_operations["scout"], *ops})
    return _manifest(allowed_operations={**m.allowed_operations, "scout": scout})


def _surface(snap: Snapshot) -> list[str]:
    return [n.reason for n in snap.coverage.not_collected if n.surface == APP_CREDENTIALS]


# --- without the operations nothing changes ----------------------------------------------


def test_a_scope_without_the_reads_collects_what_it_did_before() -> None:
    r = run()
    assert r.snapshot.digest() == GOLDEN
    assert r.snapshot.credentials == ()
    assert CREDENTIALS_COLLECTOR not in {c.name for c in r.snapshot.coverage.collectors}
    (default,) = [n for n in NOT_COLLECTED if n.surface == APP_CREDENTIALS]
    assert _surface(r.snapshot) == [default.reason]
    assert "credentials" not in json.loads(r.snapshot.canonical_json())


def test_no_credential_request_is_made_for_an_operation_the_scope_lacks() -> None:
    """Negative (scope gate): only the listed read is ever attempted."""
    t = WithCredentials()
    r = run(t, _with_ops(graph.OP_APPLICATION))
    ops = {q.operation for q in t.requests}
    assert graph.OP_APPLICATION in ops and graph.OP_SERVICE_PRINCIPAL not in ops
    assert {e.operation for e in r.journal.decisions} >= {graph.OP_APPLICATION}
    assert graph.OP_SERVICE_PRINCIPAL not in {e.operation for e in r.journal.decisions}
    (reason,) = _surface(r.snapshot)
    assert "GET /servicePrincipals/{id} is not in the scope" in reason


# --- with the operations ------------------------------------------------------------------


def test_metadata_is_collected_and_no_value_reaches_the_snapshot() -> None:
    bodies = {
        APPS[0]: _body(APPS[0], [_key(1)], [_password(1), _password(2)]),
        TENANT_SPS[2]: _body(TENANT_SPS[2], pws=[_password(3)]),
    }
    t = WithCredentials(bodies)
    r = run(t, _with_ops(*graph.CREDENTIAL_OPERATIONS))
    snap = r.snapshot
    creds = {(c.owner, c.kind, c.display_name) for c in snap.credentials}
    assert creds == {
        (APPS[0], "key", "cert-1"),
        (APPS[0], "password", "secret-1"),
        (APPS[0], "password", "secret-2"),
        (TENANT_SPS[2], "password", "secret-3"),
    }
    key = next(c for c in snap.credentials if c.kind == "key")
    assert (key.key_type, key.usage) == ("AsymmetricX509Cert", "Verify")
    assert key.end is not None and key.end.microsecond == 123456
    text = snap.canonical_json()
    for value in SECRETS:
        assert value not in text
    for name in ("hint", "secretText", "customKeyIdentifier", '"key":'):
        assert name not in text
    assert r.collector(CREDENTIALS_COLLECTOR).status == "complete"
    assert r.collector(CREDENTIALS_COLLECTOR).items == 4
    targets = {
        q.url.split("?")[0].rsplit("/", 1)[-1]
        for q in t.requests
        if q.operation in graph.CREDENTIAL_OPERATIONS
    }
    assert targets == {*APPS, *TENANT_SPS}  # never another tenant's service principal
    for q in t.requests:
        if q.operation in graph.CREDENTIAL_OPERATIONS:
            assert q.url.endswith(f"?$select={graph.CREDENTIAL_SELECT}")


def test_the_surface_stays_open_for_other_tenants_service_principals() -> None:
    r = run(WithCredentials(), _with_ops(*graph.CREDENTIAL_OPERATIONS))
    (reason,) = _surface(r.snapshot)
    assert reason == "metadata only; 1 service principal(s) of other tenants' applications not read"


def test_the_surface_closes_when_every_object_was_read() -> None:
    r = run(WithCredentials(drop_sp=GRAPH_SP), _with_ops(*graph.CREDENTIAL_OPERATIONS))
    assert _surface(r.snapshot) == []
    assert r.collector(CREDENTIALS_COLLECTOR).status == "complete"


def test_a_failed_read_keeps_the_surface_open() -> None:
    t = WithCredentials(status={APPS[1]: 403}, drop_sp=GRAPH_SP)
    r = run(t, _with_ops(*graph.CREDENTIAL_OPERATIONS))
    run_ = r.collector(CREDENTIALS_COLLECTOR)
    assert run_.status == "partial" and "http-403" in run_.error_codes
    (reason,) = _surface(r.snapshot)
    assert "collector graph.credentials is partial" in reason


def test_a_response_without_the_lists_is_not_read_as_no_credentials() -> None:
    t = WithCredentials({APPS[0]: {"id": APPS[0]}}, drop_sp=GRAPH_SP)
    r = run(t, _with_ops(*graph.CREDENTIAL_OPERATIONS))
    run_ = r.collector(CREDENTIALS_COLLECTOR)
    assert run_.status == "partial"
    assert {"no-keyCredentials", "no-passwordCredentials"} <= set(run_.error_codes)
    assert _surface(r.snapshot)


def test_a_response_for_another_object_is_rejected() -> None:
    t = WithCredentials({APPS[0]: _body(APPS[1], pws=[_password(1)])}, drop_sp=GRAPH_SP)
    r = run(t, _with_ops(*graph.CREDENTIAL_OPERATIONS))
    assert r.snapshot.credentials == ()
    assert "bad-response" in r.collector(CREDENTIALS_COLLECTOR).error_codes


def test_a_bad_row_is_counted_not_guessed() -> None:
    bad = [_password(1, keyId="not-a-guid"), "nope", _password(2, endDateTime="soon")]
    t = WithCredentials({APPS[0]: _body(APPS[0], pws=bad)}, drop_sp=GRAPH_SP)
    r = run(t, _with_ops(*graph.CREDENTIAL_OPERATIONS))
    assert r.snapshot.credentials == ()
    assert r.collector(CREDENTIALS_COLLECTOR).status == "partial"


def test_credentials_do_not_depend_on_read_order() -> None:
    bodies = {a: _body(a, [_key(i)], [_password(i)]) for i, a in enumerate(APPS)}
    one = run(WithCredentials(bodies), _with_ops(*graph.CREDENTIAL_OPERATIONS)).snapshot
    rev = dict(reversed(list(bodies.items())))
    two = run(WithCredentials(rev), _with_ops(*graph.CREDENTIAL_OPERATIONS)).snapshot
    assert one.digest() == two.digest()


# --- the model ------------------------------------------------------------------------------


def _cred(**changes: Any) -> dict[str, Any]:
    return {
        "owner": APPS[0],
        "kind": "password",
        "key_id": pid(950),
        "provenance": {"source_api": graph.OP_APPLICATION, "observed_at": "2026-11-28T00:00:00Z"},
        **changes,
    }


@pytest.mark.parametrize("field", ["key", "hint", "secretText", "secret_text", "value"])
def test_the_model_has_no_place_for_a_value(field: str) -> None:
    with pytest.raises(ValidationError):
        Credential.model_validate(_cred(**{field: "x"}))


def test_the_model_rejects_a_non_guid_owner_and_lowercases() -> None:
    with pytest.raises(ValidationError):
        Credential.model_validate(_cred(owner="/subscriptions/x"))
    assert Credential.model_validate(_cred(owner=APPS[0].upper())).owner == APPS[0]


def _snapshot(creds: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": 1,
        "mode": "FIXTURE",
        "tenant_id": pid(1),
        "collected_at": "2026-11-28T00:00:00Z",
        "collector_version": "fns test",
        "entities": [{"id": APPS[0], "type": "application"}],
        "credentials": creds,
    }


def test_the_snapshot_rejects_orphan_and_duplicate_credentials() -> None:
    with pytest.raises(ValidationError, match="unknown entities"):
        Snapshot.model_validate(_snapshot([_cred(owner=APPS[1])]))
    with pytest.raises(ValidationError, match="duplicate credential"):
        Snapshot.model_validate(_snapshot([_cred(), _cred(display_name="again")]))
    snap = Snapshot.model_validate(_snapshot([_cred(key_id=pid(952)), _cred(kind="key")]))
    assert [c.kind for c in snap.credentials] == ["key", "password"]


# --- recordings -----------------------------------------------------------------------------


def test_recordings_redact_every_value_a_credential_read_returns() -> None:
    body = _body(APPS[0], [_key(1)], [_password(1)])
    out = json.dumps(sanitize(body, IdMap()))
    for value in SECRETS[:3]:
        assert value not in out
    assert out.count(REDACTED) >= 3


def test_the_summary_counts_credentials_only_when_there_are_some() -> None:
    from io import StringIO

    from rich.console import Console

    from fns.console import THEME
    from fns.summary import ScoutResult, render_summary

    def text(snap: Snapshot) -> str:
        buf = StringIO()
        result = ScoutResult(snap, snap.digest(), Path("s.json"), Path("j.db"), "run", 0)
        render_summary(result, Console(file=buf, width=200, color_system=None, theme=THEME))
        return buf.getvalue()

    assert "credentials" not in text(run().snapshot).split("not collected")[0]
    bodies = {APPS[0]: _body(APPS[0], [_key(1)], [_password(1)])}
    snap = run(WithCredentials(bodies), _with_ops(*graph.CREDENTIAL_OPERATIONS)).snapshot
    assert "credentials (metadata only): 2  (key=1  password=1)" in text(snap)
