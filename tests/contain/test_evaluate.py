"""Contract evaluation: the M2 decision table, exit codes, and the properties
that keep the model honest (never pass, monotonic, deterministic)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fns.contain import semantics as sem
from fns.contain.evaluate import Evaluation, evaluate
from fns.exitcodes import ExitCode
from fns.fixtures import wellknown as wk
from fns.models.evidence import Finding
from tests.contain.helpers import KV, RG, ST, SUB_ID, Snap, contract
from tests.factories import pid

AGENT = pid(100)


def _agent(s: Snap | None = None) -> Snap:
    s = s or Snap()
    s.sp(100, "sp-agent")
    return s


def _one(ev: Evaluation, op: str) -> Finding:
    (f,) = [o.finding for o in ev.outcomes if o.finding.operation == op]
    return f


KV_SECRETS = {"resource": "kv-crown", "operations": ["secrets/get"]}
PAYROLL = {"resource": "stpayroll", "operations": ["listKeys", "blob/read"]}


# -- decision table --------------------------------------------------------------


def test_reachable_must_not_reach_fails_at_modeled_rung() -> None:
    s = _agent()
    s.kv()
    s.rbac(AGENT, "Contributor", RG)
    f = _one(evaluate(contract([KV_SECRETS]), s.build()), "secrets/get")
    assert (f.verdict, f.coverage) == ("fail", "modeled-only")
    assert [(e.rung, e.outcome) for e in f.evidence] == [("modeled", "allowed")]
    assert f.evidence[0].source == "fns.contain/kv-control-to-data"


def test_unreachable_must_not_reach_is_inconclusive_never_pass() -> None:
    s = _agent()
    s.kv(enableRbacAuthorization=True)
    s.rbac(AGENT, "Reader", RG)
    f = _one(evaluate(contract([KV_SECRETS]), s.build()), "secrets/get")
    assert (f.verdict, f.coverage) == ("inconclusive", "modeled-only")
    assert f.evidence[0].outcome == "denied"
    assert "needs an observed denial" in f.reasons[0]


def test_unreachable_but_surface_missing_is_not_assessed() -> None:
    s = _agent()
    s.kv()  # permission model unknown, so access policies matter
    s.rbac(AGENT, "Reader", RG)
    s.missing(sem.KV_ACCESS_POLICIES)
    f = _one(evaluate(contract([KV_SECRETS]), s.build()), "secrets/get")
    assert (f.verdict, f.coverage) == ("inconclusive", "not-assessed")
    assert any(sem.KV_ACCESS_POLICIES in r for r in f.reasons)


def test_access_policy_gap_ignored_for_vaults_known_to_use_rbac() -> None:
    s = _agent()
    s.kv(enableRbacAuthorization=True)
    s.missing(sem.KV_ACCESS_POLICIES)
    f = _one(evaluate(contract([KV_SECRETS]), s.build()), "secrets/get")
    assert f.coverage == "modeled-only"


def test_pim_gap_and_incomplete_collectors_make_unreachable_not_assessed() -> None:
    s = _agent().missing(sem.PIM_ELIGIBILITY)
    s.kv(enableRbacAuthorization=True)
    f = _one(evaluate(contract([KV_SECRETS]), s.build()), "secrets/get")
    assert f.coverage == "not-assessed"
    s2 = _agent()
    s2.kv(enableRbacAuthorization=True)
    s2.collectors.append({"name": "graph.owners", "status": "partial", "error_codes": ["http-403"]})
    f2 = _one(evaluate(contract([KV_SECRETS]), s2.build()), "secrets/get")
    assert f2.coverage == "not-assessed"
    assert any("graph.owners is partial" in r for r in f2.reasons)


def test_must_still_do_allowed_is_inconclusive_d1() -> None:
    s = _agent()
    s.storage(allowSharedKeyAccess=False)
    s.rbac(AGENT, "Storage Blob Data Contributor", ST)
    ev = evaluate(
        contract([KV_SECRETS], [{"resource": "stpayroll", "operations": ["blob/read"]}]), s.build()
    )
    f = _one(ev, "blob/read")
    assert (f.item_kind, f.verdict, f.coverage) == ("must_still_do", "inconclusive", "modeled-only")
    assert "needs an observed success" in f.reasons[0]


def test_must_still_do_not_granted_fails() -> None:
    s = _agent()
    s.storage(allowSharedKeyAccess=False)
    s.kv(enableRbacAuthorization=True)
    ev = evaluate(
        contract([KV_SECRETS], [{"resource": "stpayroll", "operations": ["blob/write"]}]), s.build()
    )
    f = _one(ev, "blob/write")
    assert (f.verdict, f.coverage) == ("fail", "modeled-only")
    assert ev.summary.exit_code == ExitCode.CONTRACT_FAILED


@pytest.mark.parametrize(
    ("item", "reason"),
    [
        ({"resource": "kv-nowhere", "operations": ["secrets/get"]}, "not in the snapshot"),
        ({"resource": "kv-crown", "operations": ["certificates/get"]}, "unknown operation"),
        ({"resource": "kv-crown", "operations": ["listKeys"]}, "unknown operation semantics"),
        ({"directory": "tenant", "operations": ["users/delete"]}, "unknown operation"),
    ],
)
def test_unresolved_or_unknown_is_inconclusive(item: dict[str, Any], reason: str) -> None:
    s = _agent()
    s.kv()
    s.rbac(AGENT, "Owner", SUB_ID)
    (o,) = evaluate(contract([item]), s.build()).outcomes
    assert (o.finding.verdict, o.finding.coverage) == ("inconclusive", "not-assessed")
    assert any(reason in r for r in o.finding.reasons)


def test_ambiguous_names_are_inconclusive() -> None:
    s = _agent()
    s.kv()
    s.resource(
        f"{SUB_ID}/resourceGroups/rg-2/providers/Microsoft.KeyVault/vaults/kv-crown",
        "Microsoft.KeyVault/vaults",
    )
    s.rbac(AGENT, "Owner", SUB_ID)
    (o,) = evaluate(contract([KV_SECRETS]), s.build()).outcomes
    assert o.finding.verdict == "inconclusive"
    assert any("ambiguous" in r for r in o.finding.reasons)


def test_full_arm_id_targets_resolve() -> None:
    s = _agent()
    s.kv()
    s.rbac(AGENT, "Contributor", RG)
    ev = evaluate(contract([{"resource": KV, "operations": ["secrets/get"]}]), s.build())
    assert ev.outcomes[0].finding.verdict == "fail"


def test_unresolved_compromised_identity_makes_everything_inconclusive() -> None:
    s = _agent()
    s.kv()
    ev = evaluate(contract([KV_SECRETS], who="sp:nobody"), s.build())
    assert ev.compromised is None
    assert {o.finding.verdict for o in ev.outcomes} == {"inconclusive"}


def test_compromised_identity_by_app_id_and_object_id() -> None:
    s = _agent()
    assert evaluate(contract([KV_SECRETS], who=f"sp:{pid(5100)}"), s.build()).compromised == AGENT
    assert evaluate(contract([KV_SECRETS], who=f"objectId:{AGENT}"), s.build()).compromised == AGENT


# -- resource semantics ------------------------------------------------------------


def test_listkeys_gives_blob_access_unless_shared_key_is_off() -> None:
    s = _agent()
    s.storage()
    s.rbac(AGENT, "Contributor", RG)
    ev = evaluate(contract([PAYROLL]), s.build())
    blob = _one(ev, "blob/read")
    assert blob.verdict == "fail"
    assert any("allowSharedKeyAccess was not collected" in r for r in blob.reasons)
    s2 = _agent()
    s2.storage(allowSharedKeyAccess=False)
    s2.rbac(AGENT, "Contributor", RG)
    ev2 = evaluate(contract([PAYROLL]), s2.build())
    assert _one(ev2, "listKeys").verdict == "fail"
    assert _one(ev2, "blob/read").verdict == "inconclusive"


def test_data_actions_on_access_policy_vaults_do_not_apply() -> None:
    s = _agent()
    s.kv(enableRbacAuthorization=False)
    s.rbac(AGENT, "Key Vault Secrets Officer", KV)
    f = _one(evaluate(contract([KV_SECRETS]), s.build()), "secrets/get")
    assert f.verdict == "inconclusive"


def test_deny_assignment_removes_reach() -> None:
    s = _agent()
    s.storage(allowSharedKeyAccess=False)
    s.rbac(AGENT, "Contributor", RG)
    s.deny(AGENT, RG, ("Microsoft.Storage/storageAccounts/listKeys/action",))
    assert _one(evaluate(contract([PAYROLL]), s.build()), "listKeys").verdict == "inconclusive"


def test_grant_on_a_child_scope_counts_as_partial_reach() -> None:
    s = _agent()
    s.storage(allowSharedKeyAccess=False)
    container = f"{ST}/blobServices/default/containers/payroll"
    s.rbac(AGENT, "Storage Blob Data Contributor", container)
    ev = evaluate(contract([PAYROLL]), s.build())
    o = next(o for o in ev.outcomes if o.finding.operation == "blob/read")
    assert o.finding.verdict == "fail"
    assert o.paths[0].partial


def test_conditional_grants_are_not_evaluated() -> None:
    s = _agent()
    s.storage(allowSharedKeyAccess=False)
    s.rbac(AGENT, "Storage Blob Data Contributor", ST, condition="@Resource[x] == 'y'")
    f = _one(evaluate(contract([PAYROLL]), s.build()), "blob/read")
    assert (f.verdict, f.coverage) == ("inconclusive", "not-assessed")
    assert any("ABAC conditions" in r for r in f.reasons)


def test_resource_role_assignments_write_from_owner_not_contributor() -> None:
    item = {"resource": "kv-crown", "operations": ["roleAssignments/write"]}
    for role, verdict in (("Owner", "fail"), ("Contributor", "inconclusive")):
        s = _agent()
        s.kv()
        s.rbac(AGENT, role, RG)
        assert evaluate(contract([item]), s.build()).outcomes[0].finding.verdict == verdict


# -- directory semantics ------------------------------------------------------------

TENANT_OPS = {
    "directory": "tenant",
    "operations": ["roleAssignments/write", "applications/credentials/update"],
}


def _app_chain() -> Snap:
    s = _agent()
    s.sp(101, "app-target")
    s.app(102, "app-target", sp=pid(101))
    s.edge("owns", AGENT, pid(102)).graph_perm(AGENT, sem.APP_READWRITE_OWNEDBY)
    s.graph_perm(pid(101), sem.APPROLE_READWRITE_ALL)
    return s


def test_lab_escalation_chain_reaches_tenant_role_assignments() -> None:
    ev = evaluate(contract([TENANT_OPS]), _app_chain().build())
    ra = next(o for o in ev.outcomes if o.finding.operation == "roleAssignments/write")
    assert ra.finding.verdict == "fail"
    rules = [s.rule for s in ra.paths[0].steps]
    assert rules == [
        "assume-compromised",
        "snapshot",
        "owner-adds-credential",
        "snapshot",
        "approle-self-grant",
        "graph-permission",
    ]


def test_owned_object_permission_counts_as_tenant_credential_update_d2() -> None:
    s = _agent()
    s.app(102, "app-x")
    s.edge("owns", AGENT, pid(102)).graph_perm(AGENT, sem.APP_READWRITE_OWNEDBY)
    o = next(
        o
        for o in evaluate(contract([TENANT_OPS]), s.build()).outcomes
        if o.finding.operation == "applications/credentials/update"
    )
    assert o.finding.verdict == "fail"
    assert o.paths[0].partial


def test_directory_roles_grant_tenant_operations() -> None:
    s = _agent().dir_role(AGENT, wk.PRIVILEGED_ROLE_ADMINISTRATOR)
    ev = evaluate(contract([TENANT_OPS]), s.build())
    assert _one(ev, "roleAssignments/write").verdict == "fail"
    clean = _agent().graph_perm(AGENT, "Directory.Read.All")
    ev2 = evaluate(contract([TENANT_OPS]), clean.build())
    assert {o.finding.verdict for o in ev2.outcomes} == {"inconclusive"}


# -- summary and exit codes ------------------------------------------------------------


def _reachable_kv() -> Snap:
    s = _agent()
    s.kv(enableRbacAuthorization=True)
    s.rbac(AGENT, "Contributor", RG)
    return s


def test_exit_codes() -> None:
    # Critical over budget.
    assert evaluate(contract([KV_SECRETS]), _reachable_kv().build()).summary.exit_code == 1
    # Critical within budget, nothing else.
    tolerant = contract([KV_SECRETS], budget={"max_critical_reachable": 1})
    assert evaluate(tolerant, _reachable_kv().build()).summary.exit_code == 0
    # Inconclusive over budget: fail -> 3, warn -> 0 with a warning.
    quiet = _agent()
    quiet.kv(enableRbacAuthorization=True)
    assert evaluate(contract([KV_SECRETS]), quiet.build()).summary.exit_code == 3
    warn = evaluate(contract([KV_SECRETS], on_inconclusive="warn"), quiet.build()).summary
    assert warn.exit_code == 0
    assert warn.warning is not None and "on_inconclusive is warn" in warn.warning
    within = evaluate(contract([KV_SECRETS], budget={"max_inconclusive": 1}), quiet.build())
    assert within.summary.exit_code == 0


# -- properties ------------------------------------------------------------------------

_ROLES = [
    "Owner",
    "Contributor",
    "Reader",
    "Storage Blob Data Contributor",
    "Key Vault Secrets Officer",
    "User Access Administrator",
]
_PERMS = [
    sem.APP_READWRITE_OWNEDBY,
    sem.APP_READWRITE_ALL,
    sem.APPROLE_READWRITE_ALL,
    sem.ROLEMANAGEMENT_READWRITE,
    "Application.Read.All",
]
_CONTRACT = contract(
    [KV_SECRETS, TENANT_OPS, PAYROLL],
    [{"resource": "stinvoices", "operations": ["blob/read", "blob/write"]}],
)
INVOICES = f"{RG}/providers/Microsoft.Storage/storageAccounts/stinvoices"


@st.composite
def grants(draw: st.DrawFn) -> list[tuple[str, ...]]:
    principals = [pid(100), pid(101), pid(110)]
    scopes = [SUB_ID, RG, KV, ST, INVOICES]
    out: list[tuple[str, ...]] = []
    for _ in range(draw(st.integers(0, 6))):
        kind = draw(st.sampled_from(["rbac", "perm", "owns", "member", "deny"]))
        p = draw(st.sampled_from(principals))
        if kind == "rbac":
            out.append(("rbac", p, draw(st.sampled_from(_ROLES)), draw(st.sampled_from(scopes))))
        elif kind == "perm":
            out.append(("perm", p, draw(st.sampled_from(_PERMS))))
        elif kind == "owns":
            out.append(("owns", p, pid(102)))
        elif kind == "member":
            out.append(("member", p, pid(110)))
        else:
            out.append(
                ("deny", p, draw(st.sampled_from(scopes)), draw(st.sampled_from(["*", "*/action"])))
            )
    return list(dict.fromkeys(out))


def _world(gs: list[tuple[str, ...]], props: dict[str, Any] | None = None) -> Snap:
    s = _agent()
    s.sp(101, "app-target")
    s.app(102, "app-target", sp=pid(101))
    s.entity(pid(110), "group", "g")
    s.kv(**(props or {}))
    s.storage(**(props or {}))
    s.storage(INVOICES)
    for g in gs:
        if g[0] == "rbac":
            s.rbac(g[1], g[2], g[3])
        elif g[0] == "perm":
            s.graph_perm(g[1], g[2])
        elif g[0] == "owns":
            s.edge("owns", g[1], g[2])
        elif g[0] == "member" and g[1] != g[2]:
            s.edge("memberOf", g[1], g[2])
        elif g[0] == "deny":
            s.deny(g[1], g[2], (g[3],))
    return s


@given(
    grants(),
    st.sampled_from([{}, {"enableRbacAuthorization": True, "allowSharedKeyAccess": False}]),
)
def test_the_model_never_passes_anything(gs: list[tuple[str, ...]], props: dict[str, Any]) -> None:
    ev = evaluate(_CONTRACT, _world(gs, props).build())
    assert all(o.finding.verdict != "pass" for o in ev.outcomes)
    assert all(o.finding.evidence and o.finding.evidence[0].rung == "modeled" for o in ev.outcomes)


@given(grants(), grants())
def test_adding_grants_never_unfails_a_must_not_reach(
    a: list[tuple[str, ...]], b: list[tuple[str, ...]]
) -> None:
    no_deny = list(dict.fromkeys(g for g in a + b if g[0] != "deny"))
    small = evaluate(_CONTRACT, _world([g for g in a if g[0] != "deny"]).build())
    big = evaluate(_CONTRACT, _world(no_deny).build())
    for x, y in zip(small.outcomes, big.outcomes, strict=True):
        if x.finding.item_kind == "must_not_reach" and x.finding.verdict == "fail":
            assert y.finding.verdict == "fail", x.finding.operation


@given(grants(), st.randoms(use_true_random=False))
def test_evaluation_is_deterministic_under_input_order(gs: list[tuple[str, ...]], rnd: Any) -> None:
    shuffled = list(gs)
    rnd.shuffle(shuffled)
    a = evaluate(_CONTRACT, _world(gs).build())
    b = evaluate(_CONTRACT, _world(shuffled).build())
    assert [o.finding for o in a.outcomes] == [o.finding for o in b.outcomes]
    assert [o.paths for o in a.outcomes] == [o.paths for o in b.outcomes]


@given(grants())
def test_every_path_hop_is_a_snapshot_fact_or_a_rule(gs: list[tuple[str, ...]]) -> None:
    ev = evaluate(_CONTRACT, _world(gs).build())
    rules = {
        "assume-compromised",
        "snapshot",
        "member-of",
        "owner-adds-credential",
        "app-readwrite-all",
        "app-admin-role",
        "approle-self-grant",
        "rolemanagement-write",
        "rbac-write",
        "managed-identity",
    }
    final = {w.rule for s in sem.TABLE.values() for w in s.ways}
    for o in ev.outcomes:
        for path in o.paths:
            assert path.steps[0].rule == "assume-compromised"
            assert path.steps[-1].rule in final
            for step in path.steps[:-1]:
                assert step.rule in rules
                if step.rule == "snapshot":
                    assert step.sources, step.text
        lengths = [len(p.steps) for p in o.paths]
        assert lengths == sorted(lengths)
