"""Hypothesis fuzz tests for the write gate (M4 strike plan, "Lab objects only").

Two properties:

1. **Allowed only if every part is good.** Requests are built from parts (form,
   method, host, path trick, which object, body, plan, expiry, verb). An oracle
   decides from the parts alone, with no parser shared with the gate, and the gate
   must agree on every example: nothing outside the forms (soundness) and every
   well-formed lab write (liveness).
2. **No scope lifts the hard denylist.** Whatever the manifest says (valid, forged
   past validation, or any committed scope file with a strike block bolted on),
   a write that touches a denylisted endpoint or a first-party ID is denied with
   ``hard-deny``.
"""

from __future__ import annotations

import copy
import random
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from fns.models.operations import WRITE_FORM_OPERATIONS, parse_operation
from fns.models.scope import ScopeManifest, StrikeScope, StrikeTarget
from fns.scope.gate import Allowed, Denied, DenyReason, FrozenClock, Gate, InMemoryJournal
from fns.scope.writes import DENIED_PROVIDERS, DENIED_TOKENS, FORMS_BY_KEY
from fns.yamlio import load_yaml
from tests.factories import LATER, NOW, SP_AGENT, TENANT, pid
from tests.scope.writekit import (
    ADD_OWNER,
    ADD_PASSWORD,
    APP_ESC,
    APP_PATCH,
    APP_SCOUT,
    APP_VER,
    APPS,
    ASSIGN,
    GRAPH_APP_ID,
    LIST_KEYS,
    MARKER,
    PAYROLL,
    PRE_ROLES,
    REGEN_KEY,
    REMOVE_OWNER,
    REMOVE_PASSWORD,
    SP_ESC,
    STRIKE_UNTIL,
    TARGETS,
    UNASSIGN,
    VAULT,
    VAULT_WRITE,
    app_json,
    req,
    sp_json,
    strike_dict,
    strike_manifest,
    valid,
)

REPO = Path(__file__).resolve().parents[2]
SP_SCOUT = pid(204)
FUZZ_TARGETS = [
    *copy.deepcopy(TARGETS),
    {
        "kind": "graph-service-principal",
        "id": SP_SCOUT,
        "display_name": "sp-fns-scout",
        "application": APP_SCOUT,
    },
]
FUZZ_MANIFEST = strike_manifest(strike=strike_dict(targets=FUZZ_TARGETS))
PRIMARY: dict[str, str] = {
    ADD_PASSWORD: APP_ESC,
    REMOVE_PASSWORD: APP_ESC,
    APP_PATCH: APP_ESC,
    ASSIGN: SP_ESC,
    UNASSIGN: SP_ESC,
    ADD_OWNER: APP_VER,
    REMOVE_OWNER: APP_VER,
}
ARM_FORMS = {LIST_KEYS: PAYROLL, REGEN_KEY: PAYROLL, VAULT_WRITE: VAULT}
HOSTS = {"management.azure.com", "graph.microsoft.com"}


class Toggle:
    def __init__(self) -> None:
        self.allow = True

    def admits(self, request: Any, body_digest: str) -> bool:
        return self.allow


@dataclass(frozen=True)
class Parts:
    op: str
    method: str
    host: str  # ok | evil | suffix | upper | port | swap
    trick: str  # none | trailing | double | dotdot | pct-slash | pct-dot | semicolon | case
    #             | query | fragment
    slot: str  # target | near-miss | other-kind | unconfirmed | first-party
    body: str  # valid | extra-key | bad-value
    plan: bool
    expiry: str  # none | scope | strike
    verb: str


BAD_BODIES: dict[str, Any] = {
    LIST_KEYS: {"expand": "kerb"},
    REGEN_KEY: {"keyName": "key3"},
    VAULT_WRITE: {"properties": {"enableRbacAuthorization": False}},
    ADD_PASSWORD: {
        "passwordCredential": {"displayName": "fns-strike-x", "endDateTime": "2026-11-25T15:00:00Z"}
    },
    REMOVE_PASSWORD: {"keyId": "every"},
    APP_PATCH: {"appRoles": [MARKER]},
    ASSIGN: {"principalId": SP_AGENT, "resourceId": SP_ESC, "appRoleId": PRE_ROLES[0]["id"]},
    UNASSIGN: {"keyId": pid(1)},
    ADD_OWNER: {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{pid(101)}"},
    REMOVE_OWNER: {"x": "y"},
}


def _near(value: str) -> str:
    return value[:-1] + ("7" if value[-1] != "7" else "8")


def _swap_host(url: str, new: str) -> str:
    scheme, rest = url.split("://", 1)
    _host, path = rest.split("/", 1)
    return f"{scheme}://{new}/{path}"


def build(p: Parts, rnd: random.Random) -> Any:
    r = valid(p.op)
    url = r.url
    form = FORMS_BY_KEY[_key(p.op)]
    is_arm = form.api == "arm"

    # which object
    if is_arm:
        resource = ARM_FORMS[p.op]
        alt = {
            "near-miss": resource[:-1] + ("u" if resource[-1] != "u" else "v"),
            "other-kind": VAULT if resource == PAYROLL else PAYROLL,
        }.get(p.slot)
        if alt is not None:
            url = url.replace(resource, alt)
    else:
        primary = PRIMARY[p.op]
        is_app = primary != SP_ESC
        alt = {
            "near-miss": _near(primary),
            "other-kind": SP_ESC if is_app else APP_ESC,
            "unconfirmed": APP_SCOUT if is_app else SP_SCOUT,
            "first-party": GRAPH_APP_ID,
        }.get(p.slot)
        if alt is not None:
            url = url.replace(primary, alt)

    # path tricks
    base, sep, query = url.partition("?")
    head, last = base.rsplit("/", 1)
    tail = f"{sep}{query}"
    if p.trick == "trailing":
        url = f"{base}/{tail}"
    elif p.trick == "double":
        url = f"{head}//{last}{tail}"
    elif p.trick == "dotdot":
        url = f"{head}/x/../{last}{tail}"
    elif p.trick == "pct-slash":
        url = f"{head}%2F{last}{tail}"
    elif p.trick == "pct-dot":
        url = f"{head}/%2E/{last}{tail}"
    elif p.trick == "semicolon":
        url = f"{base};a=b{tail}"
    elif p.trick == "case":
        if is_arm:
            scheme_host, path = base.split(".com", 1)
            url = f"{scheme_host}.com{path.upper() if rnd.random() < 0.5 else path.lower()}{tail}"
        else:
            url = url.replace("/v1.0/", "/V1.0/") if rnd.random() < 0.3 else _upper_literal(url)
    elif p.trick == "query":
        url = f"{url}&x=1" if is_arm else f"{url}?x=1"
    elif p.trick == "fragment":
        url = f"{url}#f"

    # host
    host = "management.azure.com" if is_arm else "graph.microsoft.com"
    new_host = {
        "evil": "evil.example",
        "suffix": f"{host}.evil.example",
        "upper": host.upper(),
        "port": f"{host}:443",
        "swap": (HOSTS - {host}).pop(),
    }.get(p.host)
    if new_host is not None:
        url = _swap_host(url, new_host)

    body: Any = r.body
    if p.body == "extra-key":
        body = {**(body or {}), "zz": "1"}
    elif p.body == "bad-value":
        body = copy.deepcopy(BAD_BODIES[p.op])
    return replace(r, url=url, method=p.method, body=body, verb=p.verb)


def _key(op: str) -> str:
    return parse_operation(op).key


def _upper_literal(url: str) -> str:
    # Re-case one literal Graph segment ("applications" -> "Applications").
    for lit in ("applications", "servicePrincipals", "addPassword", "removePassword", "owners"):
        if f"/{lit}" in url:
            return url.replace(f"/{lit}", f"/{lit[0].swapcase()}{lit[1:]}", 1)
    return url.replace("appRoleAssignedTo", "approleassignedto")


def oracle(p: Parts) -> bool:
    form_method = FORMS_BY_KEY[_key(p.op)].method
    is_arm = p.op.startswith("arm:")
    trick_ok = p.trick == "none" or (p.trick == "case" and is_arm)
    slot_ok = p.slot == "target" or (is_arm and p.slot in {"unconfirmed", "first-party"})
    return (
        p.verb == "strike"
        and p.method == form_method
        and p.host == "ok"
        and trick_ok
        and slot_ok
        and p.body == "valid"
        and p.plan
        and p.expiry == "none"
    )


def ready_gate(p: Parts) -> Gate:
    plan = Toggle()
    clock = FrozenClock(NOW)
    gate = Gate(
        FUZZ_MANIFEST,
        signed_in_tenant=TENANT,
        journal=InMemoryJournal(),
        clock=clock,
        run_id="fuzz",
        signed_in_principal=SP_AGENT,
        plan=plan,
    )
    for oid in (APP_ESC, APP_VER):  # APP_SCOUT and SP_SCOUT stay unchecked
        assert gate.record_lab_check(oid, app_json(oid)) is None
    assert gate.record_lab_check(SP_ESC, sp_json()) is None
    gate.call_write(valid(APP_PATCH), lambda: None)  # the marker, for ASSIGN
    plan.allow = p.plan
    clock.at = {"none": NOW, "scope": LATER, "strike": STRIKE_UNTIL}[p.expiry]
    return gate


TRICKS = [
    *("none", "none", "none", "trailing", "double", "dotdot", "pct-slash", "pct-dot"),
    *("semicolon", "case", "query", "fragment"),
]
parts_st = st.builds(
    Parts,
    op=st.sampled_from(WRITE_FORM_OPERATIONS),
    method=st.sampled_from(["GET", "PUT", "POST", "PATCH", "DELETE", "post", "MERGE"]),
    host=st.sampled_from(["ok", "ok", "ok", "evil", "suffix", "upper", "port", "swap"]),
    trick=st.sampled_from(TRICKS),
    slot=st.sampled_from(["target", "target", "near-miss", "other-kind", "unconfirmed"]),
    body=st.sampled_from(["valid", "valid", "extra-key", "bad-value"]),
    plan=st.booleans(),
    expiry=st.sampled_from(["none", "none", "scope", "strike"]),
    verb=st.sampled_from(["strike", "strike", "harden", "prove"]),
)


@settings(max_examples=600)
@given(p=parts_st, seed=st.integers(0, 2**16))
def test_write_allowed_exactly_when_every_part_is_good(p: Parts, seed: int) -> None:
    # Methods are drawn uniformly, so steer half the examples to the right one;
    # otherwise almost nothing would be allowed and liveness would go untested.
    rnd = random.Random(seed)
    if rnd.random() < 0.5:
        p = replace(p, method=FORMS_BY_KEY[_key(p.op)].method)
    gate = ready_gate(p)
    d = gate.check_write(build(p, rnd))
    assert isinstance(d, Allowed) == oracle(p), (p, d)


def test_the_oracle_and_the_gate_allow_every_well_formed_form() -> None:
    # Liveness without luck: each form, every part good, and the ARM case trick.
    for op in WRITE_FORM_OPERATIONS:
        tricks = ["none", "case"] if op.startswith("arm:") else ["none"]
        for trick in tricks:
            method = FORMS_BY_KEY[_key(op)].method
            p = Parts(op, method, "ok", trick, "target", "valid", True, "none", "strike")
            assert oracle(p)
            d = ready_gate(p).check_write(build(p, random.Random(0)))
            assert isinstance(d, Allowed), (op, trick, d)


@settings(max_examples=200)
@given(p=parts_st, seed=st.integers(0, 2**16))
def test_a_first_party_object_is_always_a_hard_deny(p: Parts, seed: int) -> None:
    graph_ops = [op for op in WRITE_FORM_OPERATIONS if not op.startswith("arm:")]
    p = replace(p, op=graph_ops[seed % len(graph_ops)], slot="first-party")
    gate = ready_gate(p)
    d = gate.check_write(build(p, random.Random(seed)))
    assert isinstance(d, Denied) and d.reason is DenyReason.HARD_DENY, d


# --- property 2: the denylist ------------------------------------------------------------

DENIED_OPS = [
    "graph:POST /roleManagement/directory/roleAssignments",
    "graph:POST /directoryRoles/{id}/members/$ref",
    "graph:POST /servicePrincipals/{id}/appRoleAssignments",
    "graph:POST /oauth2PermissionGrants",
    "arm:Microsoft.Authorization/roleAssignments/write",
]


def _forged(base: ScopeManifest, extra_targets: list[str]) -> ScopeManifest:
    """A manifest that skipped validation: every op, any target, even Graph's app ID."""
    targets = [
        StrikeTarget.model_construct(kind="graph-application", id=t, display_name="x")
        for t in extra_targets
    ]
    have = base.strike.targets if base.strike else ()
    strike = StrikeScope.model_construct(expires_at=LATER, targets=(*have, *targets))
    ops = {**base.allowed_operations, "strike": (*WRITE_FORM_OPERATIONS, *DENIED_OPS)}
    return ScopeManifest.model_construct(
        **{**base.__dict__, "allowed_operations": ops, "strike": strike, "expires_at": LATER}
    )


def committed_scopes() -> list[ScopeManifest]:
    """Every scope file in the repository (the fixtures), parsed without the clock."""
    out = []
    for path in sorted(REPO.glob("fixtures/*/scope.yaml")):
        out.append(ScopeManifest.model_validate(load_yaml(path)))
    return out


def _encode(token: str, rnd: random.Random) -> str:
    out = []
    for ch in token:
        roll = rnd.random()
        if roll < 0.2:
            out.append(f"%{ord(ch):02X}")
        elif roll < 0.3:
            out.append(f"%25{ord(ch):02x}")  # double-encoded
        elif roll < 0.6:
            out.append(ch.swapcase())
        else:
            out.append(ch)
    return "".join(out)


DENY_TEXT = sorted(DENIED_TOKENS) + list(DENIED_PROVIDERS)


@settings(max_examples=500)
@given(
    which=st.integers(0, 1000),
    token=st.sampled_from(DENY_TEXT),
    where=st.sampled_from(["path", "body", "body-key", "first-party-path", "first-party-body"]),
    method=st.sampled_from(["GET", "POST", "PUT", "PATCH", "DELETE"]),
    host=st.sampled_from(["graph.microsoft.com", "management.azure.com", "evil.example"]),
    op=st.sampled_from([*WRITE_FORM_OPERATIONS, *DENIED_OPS]),
    pre=st.lists(st.sampled_from(["v1.0", "beta", "applications", pid(200), "x"]), max_size=3),
    seed=st.integers(0, 2**16),
)
def test_no_scope_can_lift_the_hard_denylist(
    which: int,
    token: str,
    where: str,
    method: str,
    host: str,
    op: str,
    pre: list[str],
    seed: int,
) -> None:
    rnd = random.Random(seed)
    bases = [FUZZ_MANIFEST, *committed_scopes()]
    base = bases[which % len(bases)]
    m = _forged(base, [GRAPH_APP_ID, str(uuid.UUID(int=which + 1))])
    gate = Gate(
        m,
        signed_in_tenant=m.tenant_id,
        journal=InMemoryJournal(),
        clock=FrozenClock(NOW),
        signed_in_principal=SP_AGENT,
        plan=Toggle(),
    )
    for oid in APPS:
        gate.record_lab_check(oid, app_json(oid))
    segs = list(pre)
    body: Any = {"keyId": pid(5)}
    if where == "path":
        segs.append(_encode(token, rnd))
    elif where == "body":
        body = {"@odata.id": f"https://graph.microsoft.com/v1.0/{_encode(token, rnd)}/{pid(9)}"}
    elif where == "body-key":
        body = {"tags": {_encode(token, rnd): "x"}}
    elif where == "first-party-path":
        segs.append(_encode(GRAPH_APP_ID, rnd) if rnd.random() < 0.5 else GRAPH_APP_ID.upper())
    else:
        body = {"principalId": SP_AGENT, "resourceId": GRAPH_APP_ID, "appRoleId": pid(9)}
    url = f"https://{host}/" + "/".join(segs or ["v1.0"])
    r = replace(req(op, method, url, body), tenant_id=str(m.tenant_id))
    d = gate.check_write(r)
    assert isinstance(d, Denied) and d.reason is DenyReason.HARD_DENY, (url, body, d)


def test_every_committed_scope_file_is_checked() -> None:
    # The fixtures hold the scope files; if they move, this test must move with them.
    assert len(committed_scopes()) >= 3
