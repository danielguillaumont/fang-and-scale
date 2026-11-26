"""Probes: the rung-2 permissions probe (mocked transport, real gate), mocks, and the runner."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from fns.adapters.azure.http import ApiRequest, ApiResponse
from fns.journal.sqlite import SqliteJournal
from fns.models.assertions import PROBE_RUNG, AssertionSet, ProbeObservation, ProbeSpec, probe_id
from fns.models.scope import ScopeManifest
from fns.probes.base import ProbeUnavailableError
from fns.probes.data_read import DataReadProbe, RoutedProbe
from fns.probes.mock import MockProbe, MockResults
from fns.probes.permissions import OPERATION, ArmPermissionsProbe, permits
from fns.probes.runner import run_probes
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal
from tests.prove.helpers import prepared

TENANT = "00000000-0000-4000-8000-000000000001"
SUB = "00000000-0000-4000-8000-000000000010"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-fns-lab"
KV = f"{RG}/providers/Microsoft.KeyVault/vaults/kv"
AGENT = "00000000-0000-4000-8000-000000000100"
NOW = datetime(2026, 11, 26, tzinfo=UTC)
FID = "c" * 64


def _manifest(ops: list[str]) -> ScopeManifest:
    return ScopeManifest.model_validate(
        {
            "version": 1,
            "tenant_id": TENANT,
            "subscription_ids": [SUB],
            "allowed_resource_groups": [RG],
            "test_identities": [{"object_id": AGENT, "kind": "servicePrincipal", "name": "a"}],
            "allowed_operations": {"prove": ops},
            "budget": {"max_api_calls": 10, "max_minutes": 5},
            "expires_at": (NOW + timedelta(days=1)).isoformat(),
        }
    )


class Fake:
    def __init__(self, resp: ApiResponse) -> None:
        self.resp = resp
        self.seen: list[ApiRequest] = []

    def fetch(self, request: ApiRequest) -> ApiResponse:
        self.seen.append(request)
        return self.resp


def _spec(action: str, *, data: bool = False) -> ProbeSpec:
    return ProbeSpec(
        id=probe_id(FID, "arm-permissions", KV, action),
        kind="arm-permissions",
        rung=PROBE_RUNG["arm-permissions"],
        purpose="direct",
        target=KV,
        action=action,
        data_plane=data,
        scope_operation=OPERATION,
    )


def _probe(
    resp: ApiResponse, ops: list[str] | None = None, *, signed_in: str | None = AGENT
) -> tuple[ArmPermissionsProbe, Fake]:
    clock = FrozenClock(NOW)
    gate = Gate(
        _manifest([OPERATION] if ops is None else ops),
        signed_in_tenant=TENANT,
        journal=InMemoryJournal(),
        clock=clock,
        signed_in_principal=signed_in,
    )
    fake = Fake(resp)
    return (
        ArmPermissionsProbe(
            gate=gate, transport=fake, tenant_id=TENANT, principal_id=AGENT, now=clock.now
        ),
        fake,
    )


CONTRIBUTOR: dict[str, Any] = {
    "value": [
        {
            "actions": ["*"],
            "notActions": ["Microsoft.Authorization/*/Write"],
            "dataActions": [],
            "notDataActions": [],
        }
    ]
}


@pytest.mark.parametrize(
    ("action", "data", "expected"),
    [
        ("Microsoft.KeyVault/vaults/write", False, "allowed"),
        ("Microsoft.Authorization/roleAssignments/write", False, "denied"),
        ("Microsoft.KeyVault/vaults/secrets/getSecret/action", True, "denied"),
    ],
)
def test_permissions_probe_evaluates_actions(action: str, data: bool, expected: str) -> None:
    probe, fake = _probe(ApiResponse(200, CONTRIBUTOR, request_id="r1"))
    obs = probe.observe(_spec(action, data=data), FID)
    assert (obs.outcome, obs.rung, obs.mode) == (expected, "evaluated", "LIVE")
    (req,) = fake.seen
    assert req.url.startswith("https://management.azure.com" + KV + "/providers/")
    assert req.operation == OPERATION


def test_permissions_probe_http_error_is_unknown_not_denied() -> None:
    probe, _ = _probe(ApiResponse(500, {}))
    assert probe.observe(_spec("Microsoft.KeyVault/vaults/write"), FID).outcome == "unknown"


def test_permissions_probe_is_gated() -> None:
    probe, fake = _probe(ApiResponse(200, CONTRIBUTOR), ops=[])
    with pytest.raises(ProbeUnavailableError, match="scope denied"):
        probe.observe(_spec("Microsoft.KeyVault/vaults/write"), FID)
    assert fake.seen == []


def test_permissions_probe_rejects_malformed_bodies() -> None:
    probe, _ = _probe(ApiResponse(200, {"value": "nope"}))
    with pytest.raises(ProbeUnavailableError, match="bad permissions"):
        probe.observe(_spec("Microsoft.KeyVault/vaults/write"), FID)
    with pytest.raises(ValueError):
        permits({"value": [1]}, "x", data_plane=False)


def test_live_data_reads_are_unavailable_until_the_gate_can_name_them() -> None:
    spec = ProbeSpec(
        id="d" * 64,
        kind="data-read",
        rung="observed",
        purpose="direct",
        target=KV,
        action="secrets/get",
    )
    with pytest.raises(ProbeUnavailableError, match=r"P5.1"):
        DataReadProbe().observe(spec, FID)
    with pytest.raises(ProbeUnavailableError, match="no probe"):
        RoutedProbe({}, mode="LIVE").observe(spec, FID)


def test_mock_rejects_duplicates() -> None:
    r = {"kind": "data-read", "resource": "kv", "action": "secrets/get", "outcome": "denied"}
    results = MockResults.model_validate({"format": 1, "label": "FIXTURE", "results": [r, r]})
    with pytest.raises(ValueError, match="duplicate"):
        MockProbe(results, at=NOW)


def test_mock_results_must_be_labelled_fixture() -> None:
    with pytest.raises(ValueError):
        MockResults.model_validate({"format": 1, "label": "LIVE", "results": []})


def test_probes_need_frozen_assertions(tmp_path: Path) -> None:
    aset, run_dir, _, lb = prepared(tmp_path)
    with SqliteJournal(tmp_path / "fresh.sqlite") as j:
        j.begin_run(aset.run_id, "prove", "FIXTURE")
        with pytest.raises(RuntimeError, match="frozen"):
            run_probes(j, aset, MockProbe(lb.results, at=NOW), run_dir, now=lambda: NOW)


class Boom:
    mode = "FIXTURE"

    def observe(self, spec: ProbeSpec, finding_id: str) -> ProbeObservation:
        raise RuntimeError("probe crashed")


def test_crashing_probe_leaves_a_failed_step_and_no_evidence(tmp_path: Path) -> None:
    from fns.verify.inputs import load_inputs

    empty = MockResults.model_validate({"format": 1, "label": "FIXTURE", "results": []})
    aset, _, first, _ = prepared(tmp_path, empty)
    assert all(o.outcome == "not-run" for o in first.observations)
    # A second run directory where every probe crashes.
    other = tmp_path / "boom"
    other.mkdir()
    from fns.probes.runner import freeze_into

    with SqliteJournal(other / "journal.sqlite") as j:
        j.begin_run(aset.run_id, "prove", aset.mode)
        freeze_into(j, aset, other)
        result = run_probes(j, aset, Boom(), other, now=lambda: NOW)  # type: ignore[arg-type]
    assert result.observations == ()
    total = sum(len(a.probes) for a in aset.assertions)
    assert len(result.failed) == total
    got = load_inputs(other)
    assert got.observations == {}
    assert len(got.unfinished) == total
    assert isinstance(aset, AssertionSet)


@pytest.mark.parametrize("signed_in", [None, "00000000-0000-4000-8000-000000000999"])
def test_permissions_probe_refuses_unless_signed_in_as_the_test_identity(
    signed_in: str | None,
) -> None:
    """Principal pinning (V4): without the agent's own token the probe never runs."""
    probe, fake = _probe(ApiResponse(200, CONTRIBUTOR), signed_in=signed_in)
    with pytest.raises(ProbeUnavailableError, match="principal-not-allowed"):
        probe.observe(_spec("Microsoft.KeyVault/vaults/write"), FID)
    assert fake.seen == []
