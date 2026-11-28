"""Group-derived reach (queue item 3, pending review).

- Nested groups: a grant on a group applies to its nested members ("Role
  assignments are transitive for groups", Azure RBAC overview).
- ``group-membership-write``: an app-only caller with GroupMember.ReadWrite.All
  (or Group.ReadWrite.All) and Application.ReadWrite.All adds itself to a group
  that holds grants; a role-assignable group also needs
  RoleManagement.ReadWrite.Directory; an unknown one is left open.
"""

from __future__ import annotations

from fns.contain import semantics as sem
from fns.contain.closure import Closure, Fact, SnapshotIndex
from fns.contain.evaluate import evaluate
from tests.contain.helpers import KV, Snap, contract
from tests.factories import pid

AGENT, GROUP, OUTER = pid(100), pid(103), pid(106)
SECRET_GET = {"resource": "kv-crown", "operations": ["secrets/get"]}


def _snap(assignable: bool | None = False) -> Snap:
    s = Snap()
    s.sp(100, "sp-agent")
    props = {} if assignable is None else {"isAssignableToRole": assignable}
    s.entity(GROUP, "group", "grp-vault", **props)
    s.kv(enableRbacAuthorization=True)
    s.rbac(GROUP, "Key Vault Secrets Officer", KV)
    return s


def _closure(s: Snap) -> Closure:
    return Closure(SnapshotIndex(s.build()), AGENT)


def _member(c: Closure, g: str = GROUP) -> bool:
    return c.has(Fact("member", AGENT, (g,)))


def test_a_grant_on_an_outer_group_reaches_a_nested_member() -> None:
    s = Snap()
    s.sp(100, "sp-agent")
    s.entity(GROUP, "group", "grp-inner")
    s.entity(OUTER, "group", "grp-outer")
    s.edge("memberOf", AGENT, GROUP).edge("memberOf", GROUP, OUTER)
    s.kv(enableRbacAuthorization=True)
    s.rbac(OUTER, "Key Vault Secrets Officer", KV)
    (o,) = evaluate(contract([SECRET_GET]), s.build()).outcomes
    assert o.finding.verdict == "fail"
    assert [st.rule for st in o.paths[0].steps].count("member-of") == 2


def test_membership_write_adds_the_caller_to_a_granted_group() -> None:
    s = _snap().graph_perm(AGENT, sem.GROUPMEMBER_READWRITE_ALL)
    s.graph_perm(AGENT, sem.APP_READWRITE_ALL)
    c = _closure(s)
    assert _member(c)
    d = c.derivations[Fact("member", AGENT, (GROUP,))]
    assert d.rule == "group-membership-write" and "adds itself to the group grp-vault" in d.text
    (o,) = evaluate(contract([SECRET_GET]), s.build()).outcomes
    assert o.finding.verdict == "fail"
    assert "group-membership-write" in [st.rule for st in o.paths[0].steps]


def test_group_readwrite_all_counts_for_an_ordinary_group() -> None:
    s = _snap().graph_perm(AGENT, sem.GROUP_READWRITE_ALL)
    assert _member(_closure(s.graph_perm(AGENT, sem.APP_READWRITE_ALL)))


def test_adding_a_service_principal_also_needs_application_readwrite_all() -> None:
    """Negative: GroupMember.ReadWrite.All alone does not add a service principal."""
    s = _snap().graph_perm(AGENT, sem.GROUPMEMBER_READWRITE_ALL)
    assert not _member(_closure(s))


def test_a_role_assignable_group_needs_rolemanagement() -> None:
    s = _snap(True).graph_perm(AGENT, sem.GROUPMEMBER_READWRITE_ALL)
    s.graph_perm(AGENT, sem.APP_READWRITE_ALL)
    assert not _member(_closure(s))
    s.graph_perm(AGENT, sem.ROLEMANAGEMENT_READWRITE)
    assert _member(_closure(s))


def test_group_readwrite_all_never_works_on_a_role_assignable_group() -> None:
    s = _snap(True).graph_perm(AGENT, sem.GROUP_READWRITE_ALL)
    s.graph_perm(AGENT, sem.APP_READWRITE_ALL).graph_perm(AGENT, sem.ROLEMANAGEMENT_READWRITE)
    c = _closure(s)
    assert c.derivations.get(Fact("member", AGENT, (GROUP,))) is None or (
        c.derivations[Fact("member", AGENT, (GROUP,))].rule != "group-membership-write"
    )


def test_an_unknown_group_is_left_open() -> None:
    s = _snap(None).graph_perm(AGENT, sem.GROUPMEMBER_READWRITE_ALL)
    c = _closure(s.graph_perm(AGENT, sem.APP_READWRITE_ALL))
    assert not _member(c)
    assert any("grp-vault is role-assignable was not collected" in u for u in c.uncertain)


def test_a_group_without_grants_is_not_a_target() -> None:
    s = Snap()
    s.sp(100, "sp-agent")
    s.entity(GROUP, "group", "grp-empty", isAssignableToRole=False)
    s.graph_perm(AGENT, sem.GROUPMEMBER_READWRITE_ALL).graph_perm(AGENT, sem.APP_READWRITE_ALL)
    c = _closure(s)
    assert not _member(c) and not c.uncertain


def test_the_permissions_are_self_grant_targets() -> None:
    wanted = sem.graph_permissions_in_use()
    assert {sem.GROUPMEMBER_READWRITE_ALL, sem.GROUP_READWRITE_ALL} <= wanted
