"""C1: per-resource settings (Key Vault permission model + access policies, storage
shared-key access). Mocked responses on top of the demo fixture; no Azure."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from fns.adapters.azure import arm
from fns.adapters.azure.http import ApiResponse
from fns.fixtures.replay import FixtureSet, FixtureTransport, bundled, request_key
from fns.inventory.collector import KV_ACCESS_POLICIES, Collector
from fns.models.operations import parse_operation
from fns.models.scope import parse_scope
from fns.models.snapshot import HasAccessPolicy, Snapshot
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal
from tests.factories import pid

DEMO = FixtureSet.load(bundled("demo-scout"))
TENANT = DEMO.manifest.tenant_id
RG = "/subscriptions/00000000-0000-4000-8000-000000000010/resourceGroups/rg-fns-lab"
KV = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-crown-jewels"
PAYROLL = f"{RG}/providers/Microsoft.Storage/storageAccounts/stpayroll"
INVOICES = f"{RG}/providers/Microsoft.Storage/storageAccounts/stinvoices"
AGENT = pid(100)


def _kv_body(**props: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "enableRbacAuthorization": False,
        "accessPolicies": [
            {
                "tenantId": TENANT,
                "objectId": AGENT,
                "permissions": {"secrets": ["Get", "List"], "keys": [], "certificates": []},
            }
        ],
    }
    base.update(props)
    return {"id": KV, "name": "kv-crown-jewels", "properties": base}


def _st_body(rid: str, allow: bool | None) -> dict[str, Any]:
    props: dict[str, Any] = {} if allow is None else {"allowSharedKeyAccess": allow}
    return {"id": rid, "properties": props}


def _fixture(
    responses: dict[str, ApiResponse] | None = None,
    *,
    ops: tuple[str, ...] = arm.SETTINGS_OPERATIONS,
) -> FixtureSet:
    extra = (
        responses
        if responses is not None
        else {
            KV: ApiResponse(200, _kv_body()),
            PAYROLL: ApiResponse(200, _st_body(PAYROLL, True)),
            INVOICES: ApiResponse(200, _st_body(INVOICES, None)),
        }
    )
    exchanges = list(DEMO.exchanges)
    for rid, resp in extra.items():
        rtype = (
            "microsoft.keyvault/vaults"
            if "/vaults/" in rid
            else "microsoft.storage/storageaccounts"
        )
        req = arm.resource_settings_request(rid, rtype)
        exchanges.append((request_key("GET", req.url), resp))
    scope = DEMO.scope_yaml.replace(
        "    - graph:GET /servicePrincipals\n",
        "".join(f"    - {op}\n" for op in ops) + "    - graph:GET /servicePrincipals\n",
    )
    return replace(DEMO, exchanges=tuple(exchanges), scope_yaml=scope)


def _run(fixture: FixtureSet) -> tuple[Snapshot, Gate, FixtureTransport]:
    clock = FrozenClock(fixture.recorded_at)
    manifest = parse_scope(fixture.scope_yaml, now=clock.now())
    gate = Gate(
        manifest, signed_in_tenant=str(manifest.tenant_id), journal=InMemoryJournal(), clock=clock
    )
    transport = FixtureTransport(fixture)
    snap = Collector(
        manifest=manifest,
        gate=gate,
        transport=transport,
        clock=clock,
        mode="FIXTURE",
        sleep=clock.advance,
    ).run()
    return snap, gate, transport


def _entity(snap: Snapshot, rid: str) -> dict[str, Any]:
    (e,) = [e for e in snap.entities if e.id == rid.lower()]
    return dict(e.properties)


def _status(snap: Snapshot) -> str:
    (run,) = [c for c in snap.coverage.collectors if c.name == "arm.resource-settings"]
    return run.status


def test_settings_are_collected_and_access_policies_leave_not_collected() -> None:
    snap, gate, transport = _run(_fixture())
    assert _status(snap) == "complete"
    assert _entity(snap, KV)["enableRbacAuthorization"] is False
    assert _entity(snap, PAYROLL)["allowSharedKeyAccess"] is True
    assert _entity(snap, INVOICES)["allowSharedKeyAccess"] is None  # collected, Azure default
    (policy,) = [e for e in snap.edges if isinstance(e, HasAccessPolicy)]
    assert (policy.src, policy.dst, policy.secrets) == (AGENT, KV.lower(), ("get", "list"))
    assert KV_ACCESS_POLICIES not in {n.surface for n in snap.coverage.not_collected}
    assert transport.unused() == []
    assert gate.calls_used == 28 + 3


def test_scope_without_settings_ops_makes_no_requests_and_keeps_the_gap() -> None:
    snap, gate, _ = _run(_fixture({}, ops=()))
    assert "arm.resource-settings" not in {c.name for c in snap.coverage.collectors}
    assert KV_ACCESS_POLICIES in {n.surface for n in snap.coverage.not_collected}
    assert "allowSharedKeyAccess" not in _entity(snap, PAYROLL)
    assert gate.calls_used == 28


def test_only_allowed_settings_ops_are_called() -> None:
    fx = _fixture(
        {
            PAYROLL: ApiResponse(200, _st_body(PAYROLL, False)),
            INVOICES: ApiResponse(200, _st_body(INVOICES, False)),
        },
        ops=(arm.OP_STORAGE_ACCOUNT,),
    )
    snap, _, transport = _run(fx)
    assert _status(snap) == "complete"
    assert _entity(snap, PAYROLL)["allowSharedKeyAccess"] is False
    assert "enableRbacAuthorization" not in _entity(snap, KV)
    assert KV_ACCESS_POLICIES in {n.surface for n in snap.coverage.not_collected}
    assert all("/vaults/" not in key for key in transport.served)


def test_forbidden_vault_read_is_partial_and_keeps_the_gap() -> None:
    fx = _fixture(
        {
            KV: ApiResponse(403, {"error": {"code": "AuthorizationFailed"}}),
            PAYROLL: ApiResponse(200, _st_body(PAYROLL, True)),
            INVOICES: ApiResponse(200, _st_body(INVOICES, True)),
        }
    )
    snap, _, _ = _run(fx)
    assert _status(snap) == "partial"
    assert KV_ACCESS_POLICIES in {n.surface for n in snap.coverage.not_collected}
    assert "enableRbacAuthorization" not in _entity(snap, KV)


def test_foreign_tenant_policies_are_skipped() -> None:
    body = _kv_body(
        accessPolicies=[
            {"tenantId": pid(999), "objectId": AGENT, "permissions": {"secrets": ["all"]}},
        ]
    )
    fx = _fixture(
        {
            KV: ApiResponse(200, body),
            PAYROLL: ApiResponse(200, _st_body(PAYROLL, True)),
            INVOICES: ApiResponse(200, _st_body(INVOICES, True)),
        }
    )
    snap, _, _ = _run(fx)
    (run,) = [c for c in snap.coverage.collectors if c.name == "arm.resource-settings"]
    assert "foreign-tenant-policy" in run.error_codes
    assert not [e for e in snap.edges if isinstance(e, HasAccessPolicy)]


def test_mismatched_or_malformed_response_is_a_failure() -> None:
    fx = _fixture(
        {
            KV: ApiResponse(
                200, {**_kv_body(), "id": f"{RG}/providers/Microsoft.KeyVault/vaults/other"}
            ),
            PAYROLL: ApiResponse(
                200, {"id": PAYROLL, "properties": {"allowSharedKeyAccess": "yes"}}
            ),
            INVOICES: ApiResponse(200, _st_body(INVOICES, True)),
        }
    )
    snap, _, _ = _run(fx)
    (run,) = [c for c in snap.coverage.collectors if c.name == "arm.resource-settings"]
    assert run.status == "partial"
    assert "bad-response" in run.error_codes
    assert "allowSharedKeyAccess" not in _entity(snap, PAYROLL)


def test_policy_for_an_uncollected_principal_is_dropped_and_reported() -> None:
    body = _kv_body(
        accessPolicies=[
            {"tenantId": TENANT, "objectId": pid(4444), "permissions": {"secrets": ["get"]}},
        ]
    )
    fx = _fixture(
        {
            KV: ApiResponse(200, body),
            PAYROLL: ApiResponse(200, _st_body(PAYROLL, True)),
            INVOICES: ApiResponse(200, _st_body(INVOICES, True)),
        }
    )
    snap, _, _ = _run(fx)
    assert not [e for e in snap.edges if isinstance(e, HasAccessPolicy)]
    assert "edges" in {n.surface for n in snap.coverage.not_collected}


def test_settings_ops_are_read_only_and_digest_is_stable() -> None:
    for op in arm.SETTINGS_OPERATIONS:
        assert parse_operation(op).is_read
    assert _run(_fixture())[0].digest() == _run(_fixture())[0].digest()


def test_contain_uses_collected_settings() -> None:
    """With settings collected, the payroll blob path needs no assumed default."""
    from fns.contain.evaluate import evaluate
    from fns.contain_run import demo_contract

    snap, _, _ = _run(_fixture())
    ev = evaluate(demo_contract(None), snap)
    for o in ev.outcomes:
        for p in o.paths:
            assert not any("was not collected" in a for a in p.assumptions), p.assumptions
    secrets = next(o for o in ev.outcomes if o.finding.operation == "secrets/get")
    rules = {p.steps[-1].rule for p in secrets.paths}
    assert "access-policy" in rules
