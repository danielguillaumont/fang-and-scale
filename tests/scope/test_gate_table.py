"""Table tests: one row per deny reason, plus allow rows."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from fns.models.scope import ScopeManifest
from fns.scope.gate import Allowed, Denied, DenyReason, FrozenClock
from fns.scope.targets import DirectoryTarget
from tests.factories import (
    KV,
    LATER,
    NOW,
    OTHER_TENANT,
    RG,
    RG2,
    SP_AGENT,
    SP_VERIFIER,
    SUB,
    SUB2,
    TENANT,
)
from tests.scope.gatekit import (
    ARM_READ,
    ARM_READ2,
    ARM_URL,
    ARM_WRITE,
    GRAPH_READ,
    GRAPH_URL,
    GRAPH_WRITE,
    LIST_KEYS,
    SUB_URL,
    make_gate,
    manifest,
)
from tests.scope.test_gate_data_plane import DATA_REASONS

D = DirectoryTarget()
KV_ROLE_DEF = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/x"


@pytest.mark.parametrize(
    ("verb", "op", "target", "tenant", "kw"),
    [
        ("scout", ARM_READ, RG, TENANT, {}),
        ("scout", ARM_READ, KV, TENANT, {}),
        ("scout", ARM_READ, f"/subscriptions/{SUB}", TENANT, {}),
        ("scout", ARM_READ2, KV_ROLE_DEF, TENANT, {}),
        ("scout", ARM_READ, RG.upper().replace("SUBSCRIPTIONS", "Subscriptions"), TENANT, {}),
        ("scout", ARM_READ, RG, TENANT.upper(), {}),
        ("scout", ARM_READ.lower(), RG, TENANT, {}),
        ("scout", ARM_READ, RG, TENANT, {"url": ARM_URL}),
        ("scout", ARM_READ, f"/subscriptions/{SUB}", TENANT, {"url": SUB_URL}),
        ("scout", ARM_READ, RG, TENANT, {"url": ARM_URL + "&$skiptoken=a", "page_of": ARM_URL}),
        ("scout", GRAPH_READ, D, TENANT, {}),
        ("scout", GRAPH_READ, D, TENANT, {"url": GRAPH_URL}),
    ],
)
def test_allowed(verb: str, op: str, target: Any, tenant: str, kw: dict[str, Any]) -> None:
    gate, _, _ = make_gate()
    decision = gate.check(verb, op, target, tenant, **kw)
    assert isinstance(decision, Allowed), decision


STRIKE = manifest(allowed_operations={"strike": [ARM_READ, ARM_WRITE], "scout": [ARM_READ]})

DENY_ROWS: list[tuple[str, DenyReason, dict[str, Any]]] = [
    ("no manifest", DenyReason.NO_MANIFEST, {"manifest": None}),
    ("wrong type", DenyReason.NO_MANIFEST, {"manifest": "scope.yaml"}),
    ("expired", DenyReason.EXPIRED, {"clock": FrozenClock(LATER)}),
    ("expired later", DenyReason.EXPIRED, {"clock": FrozenClock(LATER + timedelta(days=1))}),
    ("signed in elsewhere", DenyReason.TENANT_MISMATCH, {"signed_in": OTHER_TENANT}),
    ("call to other tenant", DenyReason.TENANT_MISMATCH, {"tenant": OTHER_TENANT}),
    ("tenant braces", DenyReason.TENANT_MISMATCH, {"tenant": "{" + TENANT + "}"}),
    ("tenant garbage", DenyReason.TENANT_MISMATCH, {"tenant": "contoso.onmicrosoft.com"}),
    ("verb not in manifest", DenyReason.VERB_NOT_ALLOWED, {"verb": "contain"}),
    ("unknown verb", DenyReason.VERB_NOT_ALLOWED, {"verb": "deploy"}),
    ("malformed op", DenyReason.MALFORMED_OPERATION, {"op": "arm:*/read"}),
    (
        "op not listed",
        DenyReason.OPERATION_NOT_ALLOWED,
        {"op": "arm:Microsoft.Authorization/denyAssignments/read"},
    ),
    ("write not listed", DenyReason.OPERATION_NOT_ALLOWED, {"op": ARM_WRITE}),
    ("listKeys not listed", DenyReason.OPERATION_NOT_ALLOWED, {"op": LIST_KEYS}),
    ("graph write not listed", DenyReason.OPERATION_NOT_ALLOWED, {"op": GRAPH_WRITE, "target": D}),
    (
        "strike write",
        DenyReason.WRITE_NOT_AVAILABLE_IN_M1,
        {"manifest": STRIKE, "verb": "strike", "op": ARM_WRITE, "principal": SP_AGENT},
    ),
    ("malformed target", DenyReason.MALFORMED_TARGET, {"target": "rg-fns-lab"}),
    (
        "target dot-dot",
        DenyReason.MALFORMED_TARGET,
        {"target": f"/subscriptions/{SUB}/resourceGroups/../resourceGroups/rg-fns-lab"},
    ),
    ("target encoded", DenyReason.MALFORMED_TARGET, {"target": RG + "%2F..%2Fprod"}),
    ("target trailing slash", DenyReason.MALFORMED_TARGET, {"target": RG + "/"}),
    ("target not str", DenyReason.MALFORMED_TARGET, {"target": 42}),
    ("arm op on directory", DenyReason.TARGET_KIND_MISMATCH, {"target": D}),
    ("graph op on arm", DenyReason.TARGET_KIND_MISMATCH, {"op": GRAPH_READ}),
    (
        "tenant root",
        DenyReason.TENANT_LEVEL_NOT_ALLOWED,
        {"target": "/providers/Microsoft.Authorization/roleDefinitions/x"},
    ),
    (
        "management group",
        DenyReason.MG_NOT_ALLOWED,
        {"target": "/providers/Microsoft.Management/managementGroups/root"},
    ),
    (
        "other subscription",
        DenyReason.SUBSCRIPTION_NOT_ALLOWED,
        {"target": f"/subscriptions/{SUB2}/resourceGroups/rg-fns-lab"},
    ),
    ("sibling RG", DenyReason.RG_NOT_ALLOWED, {"target": RG2}),
    ("prefix RG", DenyReason.RG_NOT_ALLOWED, {"target": RG + "-prod"}),
    ("shorter RG", DenyReason.RG_NOT_ALLOWED, {"target": RG[:-1]}),
    (
        "resource in sibling RG",
        DenyReason.RG_NOT_ALLOWED,
        {"target": f"{RG2}/providers/Microsoft.KeyVault/vaults/kv-crown-jewels"},
    ),
    (
        "url off host",
        DenyReason.BAD_URL,
        {"url": ARM_URL.replace("management.azure.com", "evil.example")},
    ),
    ("url other RG", DenyReason.BAD_URL, {"url": ARM_URL.replace("rg-fns-lab", "rg-prod")}),
    (
        "nextLink path change",
        DenyReason.BAD_URL,
        {"url": ARM_URL.replace("roleAssignments", "denyAssignments"), "page_of": ARM_URL},
    ),
    ("page_of without url", DenyReason.BAD_URL, {"page_of": ARM_URL}),
    (
        "strike as non-test identity",
        DenyReason.PRINCIPAL_NOT_ALLOWED,
        {"manifest": STRIKE, "verb": "strike", "principal": SP_VERIFIER},
    ),
    (
        "strike without identity",
        DenyReason.PRINCIPAL_NOT_ALLOWED,
        {"manifest": STRIKE, "verb": "strike"},
    ),
    (
        "call budget",
        DenyReason.BUDGET_CALLS,
        {"manifest": manifest(budget={"max_api_calls": 1, "max_minutes": 1}), "pre_calls": 1},
    ),
    (
        "time budget",
        DenyReason.BUDGET_TIME,
        {"manifest": manifest(budget={"max_api_calls": 10, "max_minutes": 1}), "advance": 60},
    ),
]


@pytest.mark.parametrize(("name", "reason", "kw"), DENY_ROWS, ids=[r[0] for r in DENY_ROWS])
def test_denied(name: str, reason: DenyReason, kw: dict[str, Any]) -> None:
    m = kw.get("manifest", manifest())
    gate, _, clock = make_gate(
        m, signed_in=kw.get("signed_in", TENANT), clock=kw.get("clock", FrozenClock(NOW))
    )
    for _ in range(kw.get("pre_calls", 0)):
        gate.call("scout", ARM_READ, RG, TENANT, lambda: None, url=ARM_URL)
    if "advance" in kw:
        clock.mono += kw["advance"]
    decision = gate.check(
        kw.get("verb", "scout"),
        kw.get("op", ARM_READ),
        kw.get("target", RG),
        kw.get("tenant", TENANT),
        kw.get("principal"),
        url=kw.get("url"),
        page_of=kw.get("page_of"),
    )
    assert isinstance(decision, Denied), decision
    assert decision.reason is reason, decision


def test_every_deny_reason_has_a_test() -> None:
    # Covered outside the table: JOURNAL_FAILED (test_gate_call), INTERNAL_ERROR (below),
    # WRITE_BY_READ_ONLY_VERB (forged manifests only; validation rejects it otherwise).
    covered = (
        {r[1] for r in DENY_ROWS}
        | DATA_REASONS
        | {
            DenyReason.JOURNAL_FAILED,
            DenyReason.INTERNAL_ERROR,
            DenyReason.WRITE_BY_READ_ONLY_VERB,
        }
    )
    assert covered == set(DenyReason)


def test_read_only_verb_write_denied_even_if_manifest_forged() -> None:
    forged = ScopeManifest.model_construct(
        **{**manifest().__dict__, "allowed_operations": {"scout": (ARM_WRITE, LIST_KEYS)}}
    )
    gate, _, _ = make_gate(forged)
    for op in (ARM_WRITE, LIST_KEYS):
        d = gate.check("scout", op, RG, TENANT)
        assert isinstance(d, Denied) and d.reason is DenyReason.WRITE_BY_READ_ONLY_VERB


def test_internal_error_fails_closed() -> None:
    class BrokenClock(FrozenClock):
        def now(self) -> Any:
            raise RuntimeError("clock broke")

    gate, _, _ = make_gate(clock=BrokenClock(NOW))
    d = gate.check("scout", ARM_READ, RG, TENANT)
    assert isinstance(d, Denied) and d.reason is DenyReason.INTERNAL_ERROR


def test_naive_clock_fails_closed() -> None:
    gate, _, _ = make_gate(clock=FrozenClock(NOW.replace(tzinfo=None)))
    d = gate.check("scout", ARM_READ, RG, TENANT)
    assert isinstance(d, Denied)


@pytest.mark.parametrize(
    "forged",
    [
        {"tenant_id": "garbage"},
        {"expires_at": NOW.replace(tzinfo=None)},
        {"allowed_resource_groups": ("not an id",)},
        {"budget": None},
    ],
)
def test_forged_manifest_with_bad_fields_denies_everything(forged: dict[str, Any]) -> None:
    m = ScopeManifest.model_construct(**{**manifest().__dict__, **forged})
    gate, _, _ = make_gate(m)
    d = gate.check("scout", ARM_READ, RG, TENANT)
    assert isinstance(d, Denied) and d.reason is DenyReason.NO_MANIFEST


def test_manifest_mutation_after_gate_creation_does_not_widen_scope() -> None:
    m = manifest()
    gate, _, _ = make_gate(m)
    m.allowed_operations["scout"] = (*m.allowed_operations["scout"], LIST_KEYS)
    m.allowed_operations["contain"] = (ARM_READ,)
    assert isinstance(gate.check("contain", ARM_READ, RG, TENANT), Denied)
