"""``fns scout`` wiring: pinning before any call, LIVE mode, --record round trip.

The transport is the bundled fixture served through the live code path; no
network is touched.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from fns.adapters.azure.http import ApiRequest, ApiResponse
from fns.cli import app
from fns.demo import run_demo_scout
from fns.fixtures.replay import FixtureSet, FixtureTransport, bundled
from fns.fixtures.sanitize import PLACEHOLDER_RE
from fns.scope.credentials import PinnedTokens, TenantMismatchError, TokenProvider
from fns.scope.gate import FrozenClock
from fns.scout import run_live_scout
from tests.factories import OTHER_TENANT
from tests.livekit import FakeCredential

FIXTURE = FixtureSet.load(bundled("demo-scout"))
TENANT = FIXTURE.manifest.tenant_id
GOLDEN = (
    (Path(__file__).parent / "golden" / "demo-scout.digest").read_text(encoding="utf-8").strip()
)


class TokenCheckingTransport:
    """Serves the fixture but insists on a pinned token for every request."""

    def __init__(self, tokens: TokenProvider) -> None:
        self.tokens = tokens
        self.inner = FixtureTransport(FIXTURE)
        self.count = 0

    def fetch(self, request: ApiRequest) -> ApiResponse:
        self.tokens.token(request.api)
        self.count += 1
        return self.inner.fetch(request)


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    # The bundled scope expires 2026-12-02; a live scout checks the real clock.
    path = tmp_path / "scope.lab.yaml"
    path.write_text(
        FIXTURE.scope_yaml.replace("2026-12-02T12:00:00Z", "2099-01-01T00:00:00Z"), encoding="utf-8"
    )
    return path


def _run(scope_file: Path, out: Path, tids: dict[str, str | None], **kw: Any) -> Any:
    made: list[TokenCheckingTransport] = []

    def factory(tokens: TokenProvider) -> TokenCheckingTransport:
        made.append(TokenCheckingTransport(tokens))
        return made[-1]

    result = run_live_scout(
        scope_file,
        out,
        clock=FrozenClock(FIXTURE.recorded_at),
        tokens=PinnedTokens(TENANT, FakeCredential(tids)),
        transport_factory=factory,
        sleep=lambda _: None,
        **kw,
    )
    return result, made


def test_live_run_produces_a_live_snapshot(scope_file: Path, tmp_path: Path) -> None:
    result, (transport,) = _run(scope_file, tmp_path / "out", {"arm": TENANT, "graph": TENANT})
    assert result.snapshot.mode == "LIVE"
    assert result.digest != GOLDEN  # mode is part of the digest
    assert result.snapshot_path.name == f"{result.digest}.LIVE.json"
    assert transport.count == result.calls == 28


def test_tenant_mismatch_aborts_before_any_call(scope_file: Path, tmp_path: Path) -> None:
    with pytest.raises(TenantMismatchError):
        _run(scope_file, tmp_path / "out", {"arm": OTHER_TENANT, "graph": TENANT})
    assert not (tmp_path / "out").exists()  # no journal, no snapshot


def test_graph_token_for_another_tenant_aborts_the_run(scope_file: Path, tmp_path: Path) -> None:
    with pytest.raises(TenantMismatchError):
        _run(scope_file, tmp_path / "out", {"arm": TENANT, "graph": OTHER_TENANT})
    assert not list((tmp_path / "out").glob("snapshots/*"))


def test_record_then_replay_round_trip(scope_file: Path, tmp_path: Path) -> None:
    rec_dir = tmp_path / "fixtures" / "lab-run"
    live, _ = _run(scope_file, tmp_path / "out", {"arm": TENANT, "graph": TENANT}, record=rec_dir)
    assert live.fixture_path == rec_dir
    manifest = json.loads((rec_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["label"] == "FIXTURE"
    assert PLACEHOLDER_RE.match(manifest["tenant_id"])

    replay = run_demo_scout(tmp_path / "replay", rec_dir)
    assert replay.snapshot.mode == "FIXTURE"
    assert len(replay.snapshot.entities) == len(live.snapshot.entities)
    assert len(replay.snapshot.edges) == len(live.snapshot.edges)
    assert [c.status for c in replay.snapshot.coverage.collectors] == [
        c.status for c in live.snapshot.coverage.collectors
    ]


def test_cli_tenant_mismatch_exits_4_without_network(
    scope_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import fns.adapters.azure.live as live
    import fns.scope.credentials as creds

    monkeypatch.setattr(
        creds, "_cli_credential", lambda tenant: FakeCredential({"arm": OTHER_TENANT})
    )

    def no_network() -> None:
        raise AssertionError("network opener must not be built")

    monkeypatch.setattr(live, "default_opener", no_network)
    result = CliRunner().invoke(
        app, ["scout", "--scope", str(scope_file), "--out", str(tmp_path / "out")]
    )
    assert result.exit_code == 4, result.output
    assert "tenant pinning" in result.output


def test_cli_expired_scope_exits_2(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text(
        FIXTURE.scope_yaml.replace("2026-12-02T12:00:00Z", "2020-01-01T00:00:00Z"), encoding="utf-8"
    )
    result = CliRunner().invoke(app, ["scout", "--scope", str(path)])
    assert result.exit_code == 2
    assert "invalid scope manifest" in result.output


def test_cli_demo_replays_a_recorded_set(scope_file: Path, tmp_path: Path) -> None:
    rec_dir = tmp_path / "rec"
    _run(scope_file, tmp_path / "out", {"arm": TENANT, "graph": TENANT}, record=rec_dir)
    result = CliRunner().invoke(
        app, ["demo", "scout", "--fixture", str(rec_dir), "--out", str(tmp_path / "o2")]
    )
    assert result.exit_code == 0, result.output
    assert all(line.startswith("FIXTURE ") for line in result.output.splitlines() if line.strip())
