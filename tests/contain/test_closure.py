"""Escalation rules: one positive and one negative test per primitive, plus
fixed-point properties (termination, rule-order independence)."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from fns.contain import semantics as sem
from fns.contain.closure import RULES, Closure, Fact, SnapshotIndex, app_perm, controls
from fns.fixtures import wellknown as wk
from tests.contain.helpers import RG, VM, Snap
from tests.factories import pid

AGENT = pid(100)
TARGET_SP = pid(101)
TARGET_APP = pid(102)
GROUP = pid(103)
MI = pid(104)


def _closure(s: Snap, who: str = AGENT) -> Closure:
    return Closure(SnapshotIndex(s.build()), who.lower())


def _base() -> Snap:
    s = Snap()
    s.sp(100, "sp-agent")
    s.sp(101, "app-target")
    s.app(102, "app-target", sp=TARGET_SP)
    return s


def test_compromised_identity_is_controlled_and_nothing_else_by_default() -> None:
    c = _closure(_base())
    assert c.controlled() == [AGENT]


def test_owner_adds_credential() -> None:
    s = _base().edge("owns", AGENT, TARGET_APP).graph_perm(AGENT, sem.APP_READWRITE_OWNEDBY)
    c = _closure(s)
    assert c.has(controls(TARGET_SP))
    d = c.derivations[controls(TARGET_SP)]
    assert d.rule == "owner-adds-credential"
    assert app_perm(AGENT, sem.APP_READWRITE_OWNEDBY) in d.premises


def test_owner_adds_credential_on_an_owned_service_principal() -> None:
    s = _base().edge("owns", AGENT, TARGET_SP).graph_perm(AGENT, sem.APP_READWRITE_OWNEDBY)
    assert _closure(s).has(controls(TARGET_SP))


def test_owning_without_a_graph_permission_is_not_enough() -> None:
    s = _base().edge("owns", AGENT, TARGET_APP).graph_perm(AGENT, "Application.Read.All")
    assert not _closure(s).has(controls(TARGET_SP))


def test_permission_on_a_resource_other_than_graph_is_ignored() -> None:
    s = _base().edge("owns", AGENT, TARGET_APP)
    s.sp(150, "Other API")
    s.edge(
        "hasAppRole",
        AGENT,
        pid(150),
        app_role_id=pid(151),
        app_role_value=sem.APP_READWRITE_OWNEDBY,
    )
    assert not _closure(s).has(controls(TARGET_SP))


def test_app_readwrite_all_reaches_every_tenant_app() -> None:
    s = _base().graph_perm(AGENT, sem.APP_READWRITE_ALL)
    c = _closure(s)
    assert c.has(controls(TARGET_SP))
    assert c.derivations[controls(TARGET_SP)].rule == "app-readwrite-all"
    assert not _closure(_base().graph_perm(AGENT, "Application.Read.All")).has(controls(TARGET_SP))


def test_app_admin_directory_role_tenant_wide_and_scoped() -> None:
    s = _base().dir_role(AGENT, wk.APPLICATION_ADMINISTRATOR)
    assert _closure(s).has(controls(TARGET_SP))
    scoped = _base().dir_role(AGENT, wk.CLOUD_APPLICATION_ADMINISTRATOR, f"/{TARGET_APP}")
    assert _closure(scoped).has(controls(TARGET_SP))
    elsewhere = _base().dir_role(AGENT, wk.CLOUD_APPLICATION_ADMINISTRATOR, f"/{pid(999)}")
    assert not _closure(elsewhere).has(controls(TARGET_SP))
    reader = _base().dir_role(AGENT, wk.DIRECTORY_READERS)
    assert not _closure(reader).has(controls(TARGET_SP))


def test_approle_self_grant_gives_every_relevant_graph_permission() -> None:
    s = _base().graph_perm(AGENT, sem.APPROLE_READWRITE_ALL)
    c = _closure(s)
    for value in sem.graph_permissions_in_use():
        assert c.has(app_perm(AGENT, value)), value
    # ... and through it, every tenant app (Application.ReadWrite.All).
    assert c.has(controls(TARGET_SP))
    assert not _closure(_base().graph_perm(AGENT, "AppRoleAssignment.Read.All")).has(
        app_perm(AGENT, sem.ROLEMANAGEMENT_READWRITE)
    )


def test_rolemanagement_write_and_privileged_role_admin_give_global_admin() -> None:
    ga = Fact("dir-role", AGENT, (wk.GLOBAL_ADMINISTRATOR, "/"))
    assert _closure(_base().graph_perm(AGENT, sem.ROLEMANAGEMENT_READWRITE)).has(ga)
    assert _closure(_base().dir_role(AGENT, wk.PRIVILEGED_ROLE_ADMINISTRATOR)).has(ga)
    assert not _closure(_base().graph_perm(AGENT, "RoleManagement.Read.Directory")).has(ga)


def _any_role(principal: str, scope: str) -> Fact:
    return Fact("rbac", principal, (scope.lower(), "*", f"rbac-write:{scope.lower()}", ""))


def test_rbac_write_from_owner_or_user_access_admin() -> None:
    for role in ("Owner", "User Access Administrator"):
        c = _closure(_base().rbac(AGENT, role, RG))
        assert c.has(_any_role(AGENT, RG)), role


def test_contributor_cannot_write_role_assignments() -> None:
    assert not _closure(_base().rbac(AGENT, "Contributor", RG)).has(_any_role(AGENT, RG))


def test_rbac_write_blocked_by_deny_or_condition() -> None:
    denied = _base().rbac(AGENT, "Owner", RG).deny(AGENT, RG, ("Microsoft.Authorization/*",))
    assert not _closure(denied).has(_any_role(AGENT, RG))
    conditional = _base().rbac(AGENT, "Owner", RG, condition="@Request[x] == 'y'")
    c = _closure(conditional)
    assert not c.has(_any_role(AGENT, RG))
    assert any("ABAC condition" in u for u in c.uncertain)


def test_missing_role_definition_is_uncertain_not_ignored() -> None:
    s = _base()
    s.entity(RG, "scope")
    s.edge(
        "hasRbacRole",
        AGENT,
        RG.lower(),
        role_definition_id=f"{RG}/providers/Microsoft.Authorization/roleDefinitions/{pid(77)}",
        assignment_id=f"{RG}/providers/Microsoft.Authorization/roleAssignments/{pid(78)}",
    )
    assert any("not collected" in u for u in _closure(s).uncertain)


def test_group_grants_apply_to_members_transitively() -> None:
    s = _base()
    s.entity(GROUP, "group", "g1")
    s.entity(pid(105), "group", "g2")
    s.edge("memberOf", AGENT, GROUP).edge("memberOf", GROUP, pid(105))
    s.rbac(pid(105), "Owner", RG)
    c = _closure(s)
    assert c.effective(AGENT) == frozenset({AGENT, GROUP, pid(105)})
    assert c.has(_any_role(AGENT, RG))


def test_managed_identity_via_run_command() -> None:
    s = _base()
    s.resource(VM, "Microsoft.Compute/virtualMachines")
    s.entity(MI, "managedIdentity", "mi-batch")
    s.edge("hasIdentity", VM, MI)
    assert _closure(s.rbac(AGENT, "Virtual Machine Contributor", RG)).has(controls(MI))
    reader = _base()
    reader.resource(VM, "Microsoft.Compute/virtualMachines")
    reader.entity(MI, "managedIdentity", "mi-batch")
    reader.edge("hasIdentity", VM, MI)
    assert not _closure(reader.rbac(AGENT, "Reader", RG)).has(controls(MI))


def test_multi_hop_chain_has_shortest_derivations() -> None:
    """owner -> credential -> self-grant -> RoleManagement -> Global Admin."""
    s = _base().edge("owns", AGENT, TARGET_APP).graph_perm(AGENT, sem.APP_READWRITE_OWNEDBY)
    s.graph_perm(TARGET_SP, sem.APPROLE_READWRITE_ALL)
    c = _closure(s)
    ga = Fact("dir-role", AGENT, (wk.GLOBAL_ADMINISTRATOR, "/"))
    assert c.has(ga)
    assert c.derivations[ga].depth == 3


# -- fixed-point properties ----------------------------------------------------

_PERMS = [
    sem.APP_READWRITE_OWNEDBY,
    sem.APP_READWRITE_ALL,
    sem.APPROLE_READWRITE_ALL,
    sem.ROLEMANAGEMENT_READWRITE,
    "Application.Read.All",
]


@st.composite
def random_tenant(draw: st.DrawFn) -> Snap:
    s = Snap()
    n = draw(st.integers(2, 5))
    sps = [s.sp(100 + i, f"sp-{i}") for i in range(n)]
    apps = [s.app(200 + i, f"app-{i}", sp=sps[i]) for i in range(n)]
    for sp in sps:
        for perm in draw(st.lists(st.sampled_from(_PERMS), max_size=2, unique=True)):
            s.graph_perm(sp, perm)
    for a, b in draw(
        st.lists(st.tuples(st.sampled_from(sps), st.sampled_from(apps)), max_size=4, unique=True)
    ):
        s.edge("owns", a, b)
    for sp in draw(st.lists(st.sampled_from(sps), max_size=2, unique=True)):
        s.rbac(sp, draw(st.sampled_from(["Owner", "Contributor", "Reader"])), RG)
    return s


@given(random_tenant(), st.permutations(range(len(RULES))))
def test_fixed_point_is_independent_of_rule_order(s: Snap, order: list[int]) -> None:
    snapshot = s.build()
    who = pid(100)
    a = Closure(SnapshotIndex(snapshot), who)
    b = Closure(SnapshotIndex(snapshot), who, tuple(RULES[i] for i in order))
    assert set(a.derivations) == set(b.derivations)
    assert {f: d.depth for f, d in a.derivations.items()} == {
        f: d.depth for f, d in b.derivations.items()
    }


@given(random_tenant())
def test_every_derivation_rests_on_earlier_facts(s: Snap) -> None:
    c = Closure(SnapshotIndex(s.build()), pid(100))
    for d in c.derivations.values():
        for p in d.premises:
            assert p in c.derivations
            assert c.derivations[p].depth < d.depth


def test_rules_are_all_registered_once() -> None:
    names = [r.__name__ for r in RULES]
    assert len(names) == len(set(names)) == 8
