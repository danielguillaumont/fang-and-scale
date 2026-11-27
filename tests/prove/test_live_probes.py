"""Live probes (M3 P5) against fake openers: no network, real gate, real verifier.

Covers the data-plane transport, the V5 outcome rule, the V6 synthetic pre-flight,
principal pinning from the token (V4), request sharing, the recording, and a test
that fails if any byte of a secret value could be persisted anywhere.
"""

from __future__ import annotations

import base64
import io
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from fns.adapters.azure.dataplane import (
    MAX_ERROR_BYTES,
    STORAGE_VERSION,
    DataPlaneTransport,
    DataRequest,
    DataResponse,
)
from fns.adapters.azure.http import TransportError
from fns.adapters.azure.live import HttpTransport
from fns.contain_run import demo_contract
from fns.demo import run_demo_scout
from fns.journal.sqlite import SqliteJournal
from fns.models.assertions import ProbeSpec, probe_id
from fns.models.scope import ScopeManifest, load_scope
from fns.models.snapshot import Snapshot
from fns.probes.base import ProbeUnavailableError
from fns.probes.data_read import DataReadProbe, classify
from fns.prove.live import (
    LiveProveError,
    ProberNotAllowedError,
    SharedRequests,
    check_prober,
    run_live_prove,
)
from fns.scope.credentials import (
    CredentialError,
    PinnedTokens,
    PrincipalMismatchError,
    SignedInIdentity,
)
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal
from fns.scope.targets import ArmTarget
from tests.livekit import fake_jwt

ROOT = Path(__file__).resolve().parents[2]
LAB_RUN = ROOT / "fixtures" / "lab-run-2"
TENANT = "00000000-0000-4000-8000-000000000002"
SUB = "00000000-0000-4000-8000-000000000001"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-fns-lab"
AGENT = "00000000-0000-4000-8000-000000000007"
AGENT_APP = "00000000-0000-4000-8000-000000000907"
SCOUT = "00000000-0000-4000-8000-000000000008"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-crown-tiin02"
PAYROLL = f"{RG}/providers/Microsoft.Storage/storageAccounts/stpayrolltiin02"
INVOICES = f"{RG}/providers/Microsoft.Storage/storageAccounts/stinvoicestiin02"
NOW = datetime(2026, 11, 26, 18, 30, tzinfo=UTC)
SECRET_NAME = "payroll-db-password"  # noqa: S105 - the lab secret's name, not a value
KV = "https://kv-crown-tiin02.vault.azure.net"
PAY_URL = "https://stpayrolltiin02.blob.core.windows.net/payroll/employees-SYNTHETIC.csv"
INV_URL = "https://stinvoicestiin02.blob.core.windows.net/invoices/invoice-0001-SYNTHETIC.json"
SECRET_URL = f"{KV}/secrets/{SECRET_NAME}?api-version=7.4"
LIST_URL = f"{KV}/secrets?api-version=7.4"
CANARY = "zq7Xw9kVb3Rm8Tn2Lp5Hd4Fs6Gj1Ky0C"
"""Stands in for the secret value. It must never appear in anything the run writes."""

PROVE_OPS = [
    "arm:Microsoft.Authorization/permissions/read",
    "arm:Microsoft.KeyVault/vaults/secrets/read",
    "kv:GET /secrets",
    f"kv:GET /secrets/{SECRET_NAME}",
    "blob:HEAD /payroll/employees-SYNTHETIC.csv",
    "blob:HEAD /invoices/invoice-0001-SYNTHETIC.json",
]
DATA_OBJECTS = [
    {"resource": VAULT, "operation": f"kv:GET /secrets/{SECRET_NAME}"},
    {"resource": PAYROLL, "operation": "blob:HEAD /payroll/employees-SYNTHETIC.csv"},
    {"resource": INVOICES, "operation": "blob:HEAD /invoices/invoice-0001-SYNTHETIC.json"},
]


def scope_doc(**overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "version": 1,
        "tenant_id": TENANT,
        "subscription_ids": [SUB],
        "allowed_resource_groups": [RG],
        "test_identities": [
            {
                "object_id": AGENT,
                "kind": "servicePrincipal",
                "name": "sp-billing-agent",
                "app_id": AGENT_APP,
            }
        ],
        "allowed_operations": {"prove": list(PROVE_OPS)},
        "data_objects": list(DATA_OBJECTS),
        "budget": {"max_api_calls": 50, "max_minutes": 15},
        "expires_at": (NOW + timedelta(days=5)).isoformat(),
    }
    doc.update(overrides)
    return doc


# --- fakes -----------------------------------------------------------------------


@dataclass
class Token:
    token: str
    expires_on: int = 10_000


@dataclass
class Cred:
    """Tokens for any audience; ``oid`` per audience can be overridden."""

    oid: str = AGENT
    appid: str = AGENT_APP
    per_scope_oid: dict[str, str] = field(default_factory=dict)

    def get_token(self, *scopes: str, **_: Any) -> Token:
        (scope,) = scopes
        oid = next((v for k, v in self.per_scope_oid.items() if k in scope), self.oid)
        return Token(fake_jwt(tid=TENANT, oid=oid, appid=self.appid, aud=scope))


def tokens(cred: Cred | None = None) -> PinnedTokens:
    return PinnedTokens(TENANT, cred or Cred(), wall=lambda: 0.0)


@dataclass
class Reply:
    status: int = 200
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    error: Exception | None = None


class Tracked(io.BytesIO):
    """A response stream that records every read, so tests can prove a body was not read."""

    def __init__(self, payload: bytes, reads: list[tuple[str, int]], url: str) -> None:
        super().__init__(payload)
        self._reads = reads
        self._url = url

    def read(self, size: int | None = -1) -> bytes:
        self._reads.append((self._url, -1 if size is None else size))
        return super().read(size)


class Resp(Tracked):
    def __init__(self, status: int, payload: bytes, headers: Message, reads: Any, url: str) -> None:
        super().__init__(payload, reads, url)
        self.status = status
        self.headers = headers


@dataclass
class Router:
    route: Callable[[urllib.request.Request], Reply]
    requests: list[urllib.request.Request] = field(default_factory=list)
    reads: list[tuple[str, int]] = field(default_factory=list)

    def open(self, req: urllib.request.Request, data: None = None, timeout: Any = None) -> Any:
        self.requests.append(req)
        reply = self.route(req)
        if reply.error is not None:
            raise reply.error
        raw = reply.body if isinstance(reply.body, bytes) else json.dumps(reply.body or {}).encode()
        hdrs = Message()
        for k, v in reply.headers.items():
            hdrs[k] = v
        if reply.status >= 300:
            stream = Tracked(raw, self.reads, req.full_url)
            raise urllib.error.HTTPError(req.full_url, reply.status, "error", hdrs, stream)
        return Resp(reply.status, raw, hdrs, self.reads, req.full_url)


CONTRIBUTOR = {
    "actions": ["*"],
    "notActions": [
        "Microsoft.Authorization/*/Delete",
        "Microsoft.Authorization/*/Write",
        "Microsoft.Authorization/elevateAccess/Action",
    ],
    "dataActions": [],
    "notDataActions": [],
}
BLOB_DATA_CONTRIBUTOR = {
    "actions": [],
    "notActions": [],
    "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"],
    "notDataActions": [],
}
KV_DENIED = {
    "error": {
        "code": "Forbidden",
        "message": f"Caller is not authorized. {CANARY}",
        "innerError": {"code": "ForbiddenByRbac"},
    }
}
SECRET_METADATA = {
    "id": f"{VAULT}/secrets/{SECRET_NAME}",
    "name": SECRET_NAME,
    "tags": {"project": "fang-and-scale", "purpose": "lab", "fns-data": "synthetic"},
    "properties": {"contentType": "synthetic; Fang & Scale lab"},
}


def lab_routes(*, kv_get: Reply | None = None, metadata: Any = SECRET_METADATA) -> Router:
    """Answers shaped like the lab: the documented denials, and invoices readable."""

    def route(req: urllib.request.Request) -> Reply:
        url = req.full_url
        if "/providers/Microsoft.Authorization/permissions" in url:
            body = [CONTRIBUTOR] + ([BLOB_DATA_CONTRIBUTOR] if "stinvoices" in url else [])
            return Reply(body={"value": body})
        parts = urllib.parse.urlsplit(url)
        if (
            parts.scheme == "https"
            and parts.hostname == "management.azure.com"
            and "/secrets/" in parts.path
        ):
            return Reply(body=metadata)
        if url == SECRET_URL:
            return kv_get or Reply(403, KV_DENIED)
        if url == LIST_URL:
            return Reply(403, KV_DENIED)
        if url == PAY_URL:
            return Reply(403, b"", {"x-ms-error-code": "AuthorizationPermissionMismatch"})
        if url == INV_URL:
            return Reply(200, b"", {"x-ms-request-id": "r-inv"})
        raise AssertionError(f"unexpected request {req.get_method()} {url}")

    return Router(route)


# --- data-plane transport ---------------------------------------------------------


def _req(api: str = "kv", url: str = SECRET_URL, op: str | None = None) -> DataRequest:
    default = f"kv:GET /secrets/{SECRET_NAME}" if api == "kv" else "blob:HEAD /payroll/x.csv"
    return DataRequest(api=api, operation=op or default, target=ArmTarget.parse(VAULT), url=url)  # type: ignore[arg-type]


def test_kv_get_sends_a_bearer_token_and_never_reads_a_success_body() -> None:
    router = Router(lambda r: Reply(200, {"value": CANARY}, {"x-ms-request-id": "r1"}))
    resp = DataPlaneTransport(tokens(), opener=router).fetch(_req())
    assert resp == DataResponse(200, "r1", None, None, resp.duration_ms)
    (req,) = router.requests
    assert req.get_method() == "GET"
    assert req.get_header("Authorization", "").startswith("Bearer ")
    assert router.reads == []  # the body was never read
    assert CANARY not in repr(resp)


def test_blob_head_sends_the_storage_version_and_no_body_is_read() -> None:
    router = Router(lambda r: Reply(200, CANARY.encode(), {"ETag": CANARY}))
    req = _req("blob", PAY_URL, "blob:HEAD /payroll/employees-SYNTHETIC.csv")
    resp = DataPlaneTransport(tokens(), opener=router).fetch(req)
    assert resp.status == 200
    (sent,) = router.requests
    assert sent.get_method() == "HEAD"
    assert sent.get_header("X-ms-version") == STORAGE_VERSION
    assert router.reads == []
    assert CANARY not in repr(resp)


def test_kv_403_keeps_only_allowlisted_codes_from_a_bounded_read() -> None:
    router = Router(lambda r: Reply(403, KV_DENIED))
    resp = DataPlaneTransport(tokens(), opener=router).fetch(_req())
    assert (resp.status, resp.error_code, resp.inner_code) == (403, "Forbidden", "ForbiddenByRbac")
    assert router.reads == [(SECRET_URL, MAX_ERROR_BYTES)]
    assert CANARY not in repr(resp)


def test_unknown_codes_become_unrecognized() -> None:
    body = {"error": {"code": CANARY, "innerError": {"code": "x" + CANARY}}}
    resp = DataPlaneTransport(tokens(), opener=Router(lambda r: Reply(403, body))).fetch(_req())
    assert (resp.error_code, resp.inner_code) == ("unrecognized", "unrecognized")


@pytest.mark.parametrize("status", [400, 404, 409, 429, 500, 503])
def test_other_error_bodies_are_not_read(status: int) -> None:
    router = Router(lambda r: Reply(status, {"value": CANARY}))
    resp = DataPlaneTransport(tokens(), opener=router).fetch(_req())
    assert resp.status == status
    assert router.reads == []


def test_network_errors_carry_no_content() -> None:
    router = Router(lambda r: Reply(error=ConnectionResetError(CANARY)))
    with pytest.raises(TransportError) as info:
        DataPlaneTransport(tokens(), opener=router).fetch(_req())
    assert CANARY not in str(info.value)
    assert info.value.__cause__ is None


@pytest.mark.parametrize(
    ("api", "url", "op"),
    [
        ("kv", SECRET_URL.replace("https", "http"), None),
        ("kv", SECRET_URL.replace(".net/", ".net:8443/"), None),
        ("kv", "https://evil.example/secrets/x?api-version=7.4", None),
        ("kv", PAY_URL, None),
        ("blob", SECRET_URL, "blob:HEAD /payroll/employees-SYNTHETIC.csv"),
        ("kv", SECRET_URL, "blob:HEAD /payroll/employees-SYNTHETIC.csv"),
        ("kv", SECRET_URL, "arm:Microsoft.KeyVault/vaults/read"),
    ],
)
def test_transport_refuses(api: str, url: str, op: str | None) -> None:
    router = Router(lambda r: Reply())
    with pytest.raises(TransportError):
        DataPlaneTransport(tokens(), opener=router).fetch(_req(api, url, op))
    assert router.requests == []


# --- V5 outcome rule --------------------------------------------------------------


@pytest.mark.parametrize(
    ("api", "resp", "outcome"),
    [
        ("kv", DataResponse(200), "allowed"),
        ("blob", DataResponse(200), "allowed"),
        ("kv", DataResponse(403, None, "Forbidden", "ForbiddenByRbac"), "denied"),
        ("kv", DataResponse(403, None, "Forbidden", "AccessDenied"), "denied"),
        ("blob", DataResponse(403, None, "AuthorizationPermissionMismatch"), "denied"),
        ("kv", DataResponse(403, None, "Forbidden", "ForbiddenByFirewall"), "unknown"),
        ("kv", DataResponse(403, None, "Forbidden", None), "unknown"),
        ("kv", DataResponse(403, None, "unrecognized", "unrecognized"), "unknown"),
        ("kv", DataResponse(403), "unknown"),
        ("blob", DataResponse(403, None, "AuthorizationFailure"), "unknown"),
        ("blob", DataResponse(403, None, "AuthorizationSourceIPMismatch"), "unknown"),
        ("blob", DataResponse(403, None, "Forbidden", "ForbiddenByRbac"), "unknown"),
        ("kv", DataResponse(401, None, "Unauthorized"), "unknown"),
        ("kv", DataResponse(400, None, "BadParameter"), "unknown"),
        ("kv", DataResponse(404, None, "SecretNotFound"), "unknown"),
        ("blob", DataResponse(404, None, "BlobNotFound"), "unknown"),
        ("kv", DataResponse(429, None, "Throttled"), "unknown"),
        ("blob", DataResponse(500), "unknown"),
        ("blob", DataResponse(503, None, "ServerBusy"), "unknown"),
        ("kv", DataResponse(302), "unknown"),
    ],
)
def test_only_authorization_answers_are_denials(api: str, resp: DataResponse, outcome: str) -> None:
    assert classify(api, resp)[0] == outcome


# --- the probe, with a real gate ---------------------------------------------------


def _spec(action: str, target: str) -> ProbeSpec:
    return ProbeSpec(
        id=probe_id("f" * 64, "data-read", target, action),
        kind="data-read",
        rung="observed",
        purpose="direct",
        target=ArmTarget.parse(target).path.format(),
        action=action,
    )


def _probe(
    router: Router, *, manifest: ScopeManifest | None = None, principal: str = AGENT
) -> DataReadProbe:
    m = manifest or ScopeManifest.model_validate(scope_doc())
    gate = Gate(
        m,
        signed_in_tenant=TENANT,
        journal=InMemoryJournal(),
        clock=FrozenClock(NOW),
        signed_in_principal=principal,
    )
    t = tokens()
    return DataReadProbe(
        gate=gate,
        transport=DataPlaneTransport(t, opener=router),
        arm_transport=HttpTransport(t, opener=router),
        manifest=m,
        tenant_id=TENANT,
        principal_id=principal,
        now=lambda: NOW,
    )


@pytest.mark.parametrize(
    ("action", "target", "outcome", "sent"),
    [
        ("secrets/get", VAULT, "denied", [("GET", "management"), ("GET", SECRET_URL)]),
        ("secrets/list", VAULT, "denied", [("GET", LIST_URL)]),
        ("blob/read", PAYROLL, "denied", [("HEAD", PAY_URL)]),
        ("blob/read", INVOICES, "allowed", [("HEAD", INV_URL)]),
    ],
)
def test_probe_sends_exactly_the_expected_requests(
    action: str, target: str, outcome: str, sent: list[tuple[str, str]]
) -> None:
    router = lab_routes()
    obs = _probe(router).observe(_spec(action, target), "f" * 64)
    assert obs.outcome == outcome
    got = [(r.get_method(), r.full_url) for r in router.requests]
    assert len(got) == len(sent)
    for (m, u), (em, eu) in zip(got, sent, strict=True):
        assert m == em
        assert eu in u
    assert CANARY not in obs.detail


@pytest.mark.parametrize(
    ("metadata", "match"),
    [
        (
            {**SECRET_METADATA, "tags": {"project": "fang-and-scale"}},
            "not tagged fns-data=synthetic",
        ),
        ({**SECRET_METADATA, "tags": {"fns-data": "real"}}, "not tagged"),
        ({k: v for k, v in SECRET_METADATA.items() if k != "tags"}, "not tagged"),
        ({**SECRET_METADATA, "name": "other-secret"}, "not the one the scope lists"),
    ],
)
def test_secret_get_needs_the_synthetic_tag_and_name(metadata: Any, match: str) -> None:
    router = lab_routes(metadata=metadata)
    with pytest.raises(ProbeUnavailableError, match=match):
        _probe(router).observe(_spec("secrets/get", VAULT), "f" * 64)
    assert all("vault.azure.net" not in r.full_url for r in router.requests)


def test_secret_get_preflight_failure_sends_no_data_plane_request() -> None:
    def route(req: urllib.request.Request) -> Reply:
        return Reply(403, {"error": {"code": "AuthorizationFailed"}})

    router = Router(route)
    with pytest.raises(ProbeUnavailableError, match="pre-flight HTTP 403"):
        _probe(router).observe(_spec("secrets/get", VAULT), "f" * 64)
    assert len(router.requests) == 1


def test_secret_get_without_the_metadata_operation_in_scope_is_not_sent() -> None:
    ops = [o for o in PROVE_OPS if "secrets/read" not in o]
    m = ScopeManifest.model_validate(scope_doc(allowed_operations={"prove": ops}))
    router = lab_routes()
    with pytest.raises(ProbeUnavailableError, match="operation-not-allowed"):
        _probe(router, manifest=m).observe(_spec("secrets/get", VAULT), "f" * 64)
    assert router.requests == []


def test_probe_as_another_principal_sends_nothing() -> None:
    router = lab_routes()
    with pytest.raises(ProbeUnavailableError, match="principal-not-allowed"):
        _probe(router, principal=SCOUT).observe(_spec("blob/read", INVOICES), "f" * 64)
    assert router.requests == []


def test_probe_without_a_bound_object_is_not_run() -> None:
    m = ScopeManifest.model_validate(scope_doc(data_objects=DATA_OBJECTS[:1]))
    with pytest.raises(ProbeUnavailableError, match="binds 0 blob"):
        _probe(lab_routes(), manifest=m).observe(_spec("blob/read", PAYROLL), "f" * 64)


# --- identity (V4) -----------------------------------------------------------------


def test_identity_comes_from_the_token_and_pins_later_tokens() -> None:
    t = tokens(Cred(per_scope_oid={"storage.azure.com": SCOUT}))
    assert t.signed_in_identity() == SignedInIdentity(AGENT, AGENT_APP)
    t.token("kv")
    with pytest.raises(PrincipalMismatchError):
        t.token("blob")


def test_identity_needs_an_oid() -> None:
    class NoOid:
        def get_token(self, *scopes: str, **_: Any) -> Token:
            return Token(fake_jwt(tid=TENANT))

    with pytest.raises(CredentialError, match="oid"):
        PinnedTokens(TENANT, NoOid()).signed_in_identity()


@pytest.mark.parametrize(
    ("who", "ok"),
    [
        (SignedInIdentity(AGENT, AGENT_APP), True),
        (SignedInIdentity(AGENT, SCOUT), False),
        (SignedInIdentity(AGENT, None), False),
        (SignedInIdentity(SCOUT, AGENT_APP), False),
    ],
)
def test_check_prober(who: SignedInIdentity, ok: bool) -> None:
    m = ScopeManifest.model_validate(scope_doc())
    if ok:
        check_prober(m, who)
    else:
        with pytest.raises(ProberNotAllowedError):
            check_prober(m, who)


def test_app_id_is_optional() -> None:
    doc = scope_doc()
    del doc["test_identities"][0]["app_id"]
    check_prober(ScopeManifest.model_validate(doc), SignedInIdentity(AGENT, None))


# --- request sharing ---------------------------------------------------------------


def test_identical_requests_are_sent_once() -> None:
    router = lab_routes()
    shared = SharedRequests(_probe(router))
    a = _spec("blob/read", INVOICES)
    b = a.model_copy(update={"id": probe_id("e" * 64, "data-read", a.target, a.action)})
    first, second = shared.observe(a, "f" * 64), shared.observe(b, "e" * 64)
    assert len(router.requests) == 1
    assert (first.probe_id, second.probe_id) == (a.id, b.id)
    assert second.outcome == first.outcome == "allowed"
    assert "sent once" in second.detail


# --- end to end: run_live_prove with the real verifier -----------------------------


@pytest.fixture(scope="module")
def live_snapshot(tmp_path_factory: pytest.TempPathFactory) -> Snapshot:
    snap = run_demo_scout(tmp_path_factory.mktemp("scout"), LAB_RUN).snapshot
    return snap.model_copy(update={"mode": "LIVE"})


def _scope_file(tmp: Path, **overrides: Any) -> Path:
    path = tmp / "scope.yaml"
    path.write_text(json.dumps(scope_doc(**overrides)), encoding="utf-8")
    return path


def _recording(tmp: Path) -> Path:
    rec = tmp / "lab-run-x"
    rec.mkdir()
    (rec / "manifest.json").write_text("{}", encoding="utf-8")
    return rec


def _run(tmp: Path, snap: Snapshot, router: Router, **kw: Any) -> Any:
    t = tokens(kw.pop("cred", None))
    return run_live_prove(
        demo_contract(LAB_RUN),
        snap,
        kw.pop("scope", None) or _scope_file(tmp),
        tmp / "out",
        clock=FrozenClock(NOW),
        tokens=t,
        arm_transport_factory=lambda tp: HttpTransport(tp, opener=router),
        data_transport_factory=lambda tp: DataPlaneTransport(tp, opener=router),
        **kw,
    )


def test_live_run_on_lab_shaped_answers(tmp_path: Path, live_snapshot: Snapshot) -> None:
    router = lab_routes()
    rec = _recording(tmp_path)
    done = _run(tmp_path, live_snapshot, router, record=rec)
    out = done.result.output
    assert "passed: 1  critical reachable: 11  still-do failed: 0  inconclusive: 1" in out, out
    assert done.result.exit_code == 1
    assert done.prober == SignedInIdentity(AGENT, AGENT_APP)
    # 9 permissions checks + 4 data reads + 1 metadata pre-flight; nothing else.
    assert len(router.requests) == 14
    assert {r.get_method() for r in router.requests} == {"GET", "HEAD"}
    with SqliteJournal(done.result.run_dir / "journal.sqlite") as j:
        assert j.decision_counts(done.result.assertions.run_id) == {"allowed": 14, "denied": 0}
    recorded = json.loads((rec / "probes.json").read_text(encoding="utf-8"))
    assert recorded["label"] == "FIXTURE"
    assert recorded["source"] == "recorded-live"
    assert "Recorded from the lab" in recorded["description"]
    assert len(recorded["results"]) == 13
    assert done.omitted == ()


def test_live_run_refuses_before_any_request(tmp_path: Path, live_snapshot: Snapshot) -> None:
    router = lab_routes()
    with pytest.raises(ProberNotAllowedError):
        _run(tmp_path, live_snapshot, router, cred=Cred(oid=SCOUT))
    with pytest.raises(ProberNotAllowedError):
        _run(tmp_path, live_snapshot, router, cred=Cred(appid=SCOUT))
    with pytest.raises(LiveProveError, match="LIVE snapshot"):
        _run(tmp_path, live_snapshot.model_copy(update={"mode": "FIXTURE"}), router)
    with pytest.raises(LiveProveError, match="no scout recording"):
        _run(tmp_path, live_snapshot, router, record=tmp_path / "missing")
    assert router.requests == []


def _variants(secret: str) -> list[bytes]:
    raw = secret.encode()
    out = [
        raw,
        secret.encode("utf-16-le"),
        base64.b64encode(raw),
        base64.urlsafe_b64encode(raw),
        raw.hex().encode(),
        urllib.parse.quote(secret).encode(),
        json.dumps(secret).encode(),
    ]
    # Every 8-character window, so a truncated or partial copy is caught too.
    out += [raw[i : i + 8] for i in range(len(raw) - 7)]
    return out


def test_no_byte_of_a_secret_value_is_persisted(
    tmp_path: Path, live_snapshot: Snapshot, capsys: pytest.CaptureFixture[str]
) -> None:
    """V6: the vault *returns* the secret (worst case). Nothing anywhere may hold it.

    The canary is in the 200 body of the secret GET, in a 403 message, in error codes,
    in a header the transport does not keep, and in a network error message.
    """
    get_reply = Reply(200, {"value": CANARY, "id": f"{KV}/secrets/{SECRET_NAME}/v1"})
    base = lab_routes(kv_get=get_reply)

    def route(req: urllib.request.Request) -> Reply:
        if req.full_url == PAY_URL:
            return Reply(403, CANARY.encode(), {"x-ms-error-code": CANARY, "x-ms-meta-s": CANARY})
        if req.full_url == INV_URL:
            return Reply(error=ConnectionResetError(CANARY))
        return base.route(req)

    router = Router(route)
    rec = _recording(tmp_path)
    done = _run(tmp_path, live_snapshot, router, record=rec)
    # The secret's 200 body was never read.
    assert all(url != SECRET_URL for url, _ in router.reads)

    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert any(p.name == "journal.sqlite" for p in written)
    assert any(p.name == "probes.json" for p in written)
    blobs = [p.read_bytes() for p in written]
    captured = capsys.readouterr()
    blobs += [done.result.output.encode(), captured.out.encode(), captured.err.encode()]
    blobs += [repr(o).encode() for o in done.result.probes.observations]
    for variant in _variants(CANARY):
        for blob in blobs:
            assert variant not in blob, f"secret bytes persisted: {variant!r}"


def test_scope_file_round_trip(tmp_path: Path) -> None:
    m = load_scope(_scope_file(tmp_path), now=NOW)
    assert m.test_identities[0].app_id is not None
    assert len(m.data_objects) == 3


def test_live_and_replay_bundles_agree_on_every_verdict(
    tmp_path: Path, live_snapshot: Snapshot
) -> None:
    """Item 3 (2026-11-26): a replay of a live recording must reach the same verdicts.

    The bundle digests differ by design (mode, IDs, run ID, timestamps, verifier
    label, artifact digests). Everything a verdict rests on must not.
    """
    from fns.models.bundle import EvidenceBundle
    from fns.probes.mock import MockProbe, load_results
    from fns.prove.run import prove

    rec = _recording(tmp_path)
    live = _run(tmp_path, live_snapshot, lab_routes(), record=rec)
    fixture_snap = live_snapshot.model_copy(update={"mode": "FIXTURE"})
    probe = MockProbe(load_results(rec / "probes.json"), at=fixture_snap.collected_at)
    replay = prove(
        demo_contract(LAB_RUN),
        fixture_snap,
        probe,
        tmp_path / "replay",
        now=lambda: NOW,
        identity="fixture-replay",
    )

    def load(run_dir: Path) -> EvidenceBundle:
        return EvidenceBundle.model_validate_json((run_dir / "bundle.json").read_bytes())

    lb, rb = load(live.result.run_dir), load(replay.run_dir)
    assert lb.digest() != rb.digest()
    assert (lb.mode, rb.mode) == ("LIVE", "FIXTURE")
    assert lb.summary == rb.summary
    assert lb.contract_digest == rb.contract_digest

    def content(b: EvidenceBundle) -> dict[str, Any]:
        out = {}
        for f in b.findings:
            evidence = sorted(
                (e.rung, e.outcome, e.source, (e.notes or "").split(" (same request as probe")[0])
                for e in f.evidence
            )
            out[f.id] = (f.target, f.operation, f.verdict, f.coverage, f.gap, f.reasons, evidence)
        return out

    assert content(lb) == content(rb)
    # The one content difference: live notes say when a request was shared.
    shared = [e.notes for f in lb.findings for e in f.evidence if "sent once" in (e.notes or "")]
    assert shared
    assert not [e for f in rb.findings for e in f.evidence if "sent once" in (e.notes or "")]
