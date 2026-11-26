"""Hypothesis fuzz tests for the scope gate.

The central property is exact agreement with an independent oracle: targets
are generated from *parts* (tenant, subscription, resource group, level,
provider path), the oracle decides from those parts with plain set
membership, and the gate sees only the rendered string. No parser is shared,
so agreement means the gate allows exactly what the manifest allows:
nothing outside it (soundness) and everything inside it (liveness).
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from hypothesis import assume, given
from hypothesis import strategies as st

from fns.models.scope import ScopeManifest
from fns.scope.gate import Allowed, Denied, DenyReason, FrozenClock, ScopeDeniedError
from fns.scope.targets import DirectoryTarget
from tests.factories import LATER, NOW, RG, SUB, SUB2, TENANT, pid, scope_dict
from tests.scope.gatekit import (
    ARM_READ,
    ARM_READ2,
    ARM_URL,
    ARM_WRITE,
    GRAPH_READ,
    GRAPH_WRITE,
    LIST_KEYS,
    make_gate,
)

# Manifest under test: one tenant, two subscriptions, two RGs (one per sub).
RG_B = f"/subscriptions/{SUB2}/resourceGroups/rg-b"
SCOUT_OPS = (ARM_READ, ARM_READ2, GRAPH_READ)
MANIFEST = ScopeManifest.model_validate(
    scope_dict(
        subscription_ids=[SUB, SUB2],
        allowed_resource_groups=[RG, RG_B],
        allowed_operations={"scout": list(SCOUT_OPS), "prove": [ARM_READ]},
    )
)
ALLOWED_SUBS = {SUB, SUB2}
ALLOWED_RGS = {(SUB, "rg-fns-lab"), (SUB2, "rg-b")}
OPS_BY_VERB = {"scout": {o.lower() for o in SCOUT_OPS}, "prove": {ARM_READ.lower()}}

OTHER_SUB = pid(12)
RG_NAMES = ["rg-fns-lab", "rg-b", "rg-fns-lab-prod", "rg-fns-la", "rg-fns-lab2", "rg-bb", "rg"]
VERBS = ["scout", "prove", "contain", "strike", "harden", "molt", "deploy", ""]
OPS = [
    ARM_READ,
    ARM_READ2,
    GRAPH_READ,
    ARM_WRITE,
    LIST_KEYS,
    GRAPH_WRITE,
    "arm:Microsoft.Authorization/denyAssignments/read",
    "graph:GET /applications",
]


@dataclass(frozen=True)
class Parts:
    tenant: str
    level: str  # tenant | mg | sub | rg | resource | directory
    sub: str
    rg: str
    provider: tuple[str, str, str]
    verb: str
    op: str


def render(p: Parts, rnd: random.Random) -> Any:
    """Build the gate's target from parts, with random casing (ARM is case-insensitive)."""
    if p.level == "directory":
        return DirectoryTarget()
    ns, rtype, name = p.provider
    prov = f"/providers/{ns}/{rtype}/{name}"
    text = {
        "tenant": prov,
        "mg": "/providers/Microsoft.Management/managementGroups/mg1",
        "sub": f"/subscriptions/{p.sub}",
        "rg": f"/subscriptions/{p.sub}/resourceGroups/{p.rg}",
        "resource": f"/subscriptions/{p.sub}/resourceGroups/{p.rg}{prov}",
    }[p.level]
    return "".join(c.upper() if rnd.random() < 0.3 else c for c in text)


def oracle(p: Parts) -> bool:
    """Independent statement of the manifest's meaning."""
    if uuid.UUID(p.tenant) != uuid.UUID(TENANT):
        return False
    if p.op.lower() not in OPS_BY_VERB.get(p.verb, set()):
        return False
    if p.op.startswith("graph:"):
        return p.level == "directory"
    if p.level in {"tenant", "mg", "directory"}:
        return False
    if p.sub not in ALLOWED_SUBS:
        return False
    return p.level == "sub" or (p.sub, p.rg) in ALLOWED_RGS


# Weighted toward in-scope values so the allow/deny boundary is hit often; uniform
# sampling made in-scope tuples ~0.1% of examples and hid a planted prefix-match bug.
tenants = st.sampled_from([TENANT, TENANT, TENANT, TENANT.upper(), pid(2)]) | st.uuids().map(str)
parts_st = st.builds(
    Parts,
    tenant=tenants,
    level=st.sampled_from(["tenant", "mg", "sub", "rg", "rg", "resource", "resource", "directory"]),
    sub=st.sampled_from([SUB, SUB2, OTHER_SUB]),
    rg=st.sampled_from(RG_NAMES),
    provider=st.tuples(
        st.sampled_from(["Microsoft.KeyVault", "Microsoft.Storage", "Microsoft.Authorization"]),
        st.sampled_from(["vaults", "storageAccounts", "roleDefinitions"]),
        st.sampled_from(["kv-crown-jewels", "st-payroll", "x1"]),
    ),
    verb=st.sampled_from(["scout", "scout", "scout", "prove", *VERBS]),
    op=st.sampled_from([ARM_READ, ARM_READ, ARM_READ2, GRAPH_READ, *OPS]),
)


@given(parts=parts_st, seed=st.integers())
def test_gate_agrees_with_independent_oracle(parts: Parts, seed: int) -> None:
    gate, _, _ = make_gate(MANIFEST)
    target = render(parts, random.Random(seed))
    decision = gate.check(parts.verb, parts.op, target, parts.tenant)
    assert decision.allowed == oracle(parts), (parts, target, decision)


target_parts_st = st.builds(
    Parts,
    tenant=st.just(TENANT),
    level=st.sampled_from(["tenant", "mg", "sub", "rg", "resource"]),
    sub=st.sampled_from([SUB, SUB2, OTHER_SUB]),
    rg=st.sampled_from(RG_NAMES),
    provider=parts_st.map(lambda p: p.provider),
    verb=st.just("scout"),
    op=st.sampled_from([ARM_READ, ARM_READ2]),
)


@given(parts=target_parts_st, seed=st.integers())
def test_target_scope_agrees_with_oracle(parts: Parts, seed: int) -> None:
    """Tenant, verb and operation fixed in scope: only the ARM target varies."""
    gate, _, _ = make_gate(MANIFEST)
    target = render(parts, random.Random(seed))
    decision = gate.check(parts.verb, parts.op, target, parts.tenant)
    assert decision.allowed == oracle(parts), (parts, target, decision)


# --- mutations of an allowed ID ---------------------------------------------------------

ALLOWED_ID = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-crown-jewels"
HOMOGLYPHS = {"a": chr(0x430), "e": chr(0x435), "o": chr(0x43E), "c": chr(0x441), "l": chr(0x4CF)}


def _mutations(s: str, rnd: random.Random) -> list[str]:
    i = s.index("rg-fns-lab") + len("rg-fns-lab")
    segs = s.split("/")
    k = rnd.randrange(1, len(segs))
    homo_pos = [j for j, c in enumerate(s) if c in HOMOGLYPHS]
    j = rnd.choice(homo_pos)
    return [
        s[:i] + rnd.choice(["-prod", "2", "x", "-", "_old", ".bak"]) + s[i:],  # prefix extension
        s[: i - 1] + s[i:],  # shorter RG name
        s.replace("rg-fns-lab", "rg-b"),  # RG that exists, but in the other subscription
        s.replace(SUB, SUB2),  # subscription swap
        s.replace(SUB, OTHER_SUB),
        "/".join([*segs[:k], "", *segs[k:]]),  # empty segment
        "/".join([*segs[:k], "..", *segs[k:]]),
        "/".join([*segs[:k], ".", *segs[k:]]),
        "/".join([*segs[:k], "x", *segs[k:]]),  # extra segment
        s.replace("/resourceGroups/rg-fns-lab", "/resourceGroups/rg-fns-lab%2F..%2Frg-b"),
        s.replace("/", "%2F", 1),
        s + "/",
        "/" + s,
        s + " ",
        s[:j] + HOMOGLYPHS[s[j]] + s[j + 1 :],
    ]


@given(seed=st.integers())
def test_mutated_ids_are_denied(seed: int) -> None:
    rnd = random.Random(seed)
    gate, _, _ = make_gate(MANIFEST)
    assert gate.check("scout", ARM_READ, ALLOWED_ID, TENANT).allowed
    for mutated in _mutations(ALLOWED_ID, rnd):
        d = gate.check("scout", ARM_READ, mutated, TENANT)
        assert isinstance(d, Denied), mutated


@given(seed=st.integers())
def test_case_only_changes_are_allowed(seed: int) -> None:
    rnd = random.Random(seed)
    gate, _, _ = make_gate(MANIFEST)
    flipped = "".join(c.swapcase() if rnd.random() < 0.5 else c for c in ALLOWED_ID)
    assert gate.check("scout", ARM_READ, flipped, TENANT).allowed


# --- totality ------------------------------------------------------------------------------

anything = st.one_of(
    st.text(max_size=200),
    st.none(),
    st.integers(),
    st.binary(max_size=20),
    st.uuids(),
    st.builds(DirectoryTarget),
    st.lists(st.text(max_size=5), max_size=3),
)


@given(
    verb=anything,
    op=anything,
    target=anything,
    tenant=anything,
    principal=anything,
    url=anything,
    page_of=anything,
)
def test_check_is_total(
    verb: Any, op: Any, target: Any, tenant: Any, principal: Any, url: Any, page_of: Any
) -> None:
    gate, _, _ = make_gate(MANIFEST)
    d = gate.check(verb, op, target, tenant, principal, url=url, page_of=page_of)
    assert isinstance(d, (Allowed, Denied))


@given(verb=st.text(max_size=30), op=st.text(max_size=80), target=st.text(max_size=200))
def test_random_text_is_never_allowed_unless_in_scope(verb: str, op: str, target: str) -> None:
    gate, _, _ = make_gate(MANIFEST)
    d = gate.check(verb, op, target, TENANT)
    if d.allowed:  # only possible if hypothesis rebuilt an in-scope tuple
        assert verb in OPS_BY_VERB and op.lower() in OPS_BY_VERB[verb]


# --- expiry and tenant pinning deny everything ------------------------------------------


@given(parts=parts_st, past=st.integers(min_value=0, max_value=10**8), seed=st.integers())
def test_expired_manifest_denies_everything(parts: Parts, past: int, seed: int) -> None:
    gate, _, _ = make_gate(MANIFEST, clock=FrozenClock(LATER + timedelta(seconds=past)))
    d = gate.check(parts.verb, parts.op, render(parts, random.Random(seed)), parts.tenant)
    assert isinstance(d, Denied) and d.reason is DenyReason.EXPIRED


def _formats(u: uuid.UUID) -> st.SearchStrategy[str]:
    s = str(u)
    return st.sampled_from([s, s.upper(), "{" + s + "}", "urn:uuid:" + s, s.replace("-", "")])


@given(
    other=st.uuids().filter(lambda u: u != uuid.UUID(TENANT)).flatmap(_formats),
    where=st.sampled_from(["signed_in", "call", "both"]),
    parts=parts_st,
    seed=st.integers(),
)
def test_tenant_mismatch_denies_everything(other: str, where: str, parts: Parts, seed: int) -> None:
    signed_in = other if where in {"signed_in", "both"} else TENANT
    call_tenant = other if where in {"call", "both"} else TENANT
    gate, _, _ = make_gate(MANIFEST, signed_in=signed_in)
    d = gate.check(parts.verb, parts.op, render(parts, random.Random(seed)), call_tenant)
    assert isinstance(d, Denied) and d.reason is DenyReason.TENANT_MISMATCH


# --- monotonicity: shrinking the manifest never widens it -----------------------------


@given(
    keep_subs=st.sets(st.sampled_from([SUB, SUB2])),
    keep_rgs=st.sets(st.sampled_from([RG, RG_B])),
    keep_ops=st.sets(st.sampled_from(SCOUT_OPS)),
    parts=parts_st,
    seed=st.integers(),
)
def test_shrinking_manifest_never_turns_deny_into_allow(
    keep_subs: set[str], keep_rgs: set[str], keep_ops: set[str], parts: Parts, seed: int
) -> None:
    rgs = [r for r in keep_rgs if any(s in r for s in keep_subs)]
    try:
        smaller = ScopeManifest.model_validate(
            scope_dict(
                subscription_ids=sorted(keep_subs),
                allowed_resource_groups=sorted(rgs),
                allowed_operations={"scout": sorted(keep_ops)},
            )
        )
    except ValueError:
        assume(False)
        raise
    target = render(parts, random.Random(seed))
    full, _, _ = make_gate(MANIFEST)
    small, _, _ = make_gate(smaller)
    if small.check(parts.verb, parts.op, target, parts.tenant).allowed:
        assert full.check(parts.verb, parts.op, target, parts.tenant).allowed


# --- forged manifests: read-only verbs never write -------------------------------------


@given(
    verb=st.sampled_from(["scout", "contain", "prove", "molt"]),
    op=st.sampled_from(
        [
            ARM_WRITE,
            LIST_KEYS,
            GRAPH_WRITE,
            "arm:Microsoft.Authorization/roleAssignments/delete",
            "graph:PATCH /applications/{id}",
            "graph:DELETE /applications/{id}",
        ]
    ),
)
def test_forged_manifest_cannot_grant_writes_to_read_only_verbs(verb: str, op: str) -> None:
    forged = ScopeManifest.model_construct(
        **{**MANIFEST.__dict__, "allowed_operations": {verb: (op,)}}
    )
    gate, _, _ = make_gate(forged)
    target: Any = DirectoryTarget() if op.startswith("graph:") else RG
    d = gate.check(verb, op, target, TENANT)
    assert isinstance(d, Denied) and d.reason is DenyReason.WRITE_BY_READ_ONLY_VERB


@given(op=st.sampled_from([ARM_WRITE, LIST_KEYS]), verb=st.sampled_from(["strike", "harden"]))
def test_no_writes_in_m1_for_any_verb(op: str, verb: str) -> None:
    m = ScopeManifest.model_validate(scope_dict(allowed_operations={verb: [op]}))
    gate, _, _ = make_gate(m)
    d = gate.check(verb, op, RG, TENANT, pid(100))
    assert isinstance(d, Denied) and d.reason is DenyReason.WRITE_NOT_AVAILABLE_IN_M1


# --- budget ------------------------------------------------------------------------------------


@given(n=st.integers(min_value=1, max_value=25))
def test_exactly_n_calls_allowed(n: int) -> None:
    m = ScopeManifest.model_validate(scope_dict(budget={"max_api_calls": n, "max_minutes": 5}))
    gate, _, _ = make_gate(m)
    for _ in range(n):
        gate.call("scout", ARM_READ, RG, TENANT, lambda: None, url=ARM_URL)
    try:
        gate.call("scout", ARM_READ, RG, TENANT, lambda: None, url=ARM_URL)
    except ScopeDeniedError as exc:
        assert exc.decision.reason is DenyReason.BUDGET_CALLS
    else:
        raise AssertionError("call n+1 was allowed")
    assert gate.calls_used == n


@given(minutes=st.integers(min_value=1, max_value=60), over=st.floats(0, 3600))
def test_time_budget(minutes: int, over: float) -> None:
    m = ScopeManifest.model_validate(
        scope_dict(budget={"max_api_calls": 10, "max_minutes": minutes})
    )
    clock = FrozenClock(NOW)
    gate, _, _ = make_gate(m, clock=clock)
    clock.mono += minutes * 60 - 0.5
    assert gate.check("scout", ARM_READ, RG, TENANT).allowed
    clock.mono += 0.5 + over
    d = gate.check("scout", ARM_READ, RG, TENANT)
    assert isinstance(d, Denied) and d.reason is DenyReason.BUDGET_TIME
