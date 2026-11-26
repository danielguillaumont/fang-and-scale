"""Azure RBAC evaluation: patterns, scope relations, deny assignments."""

from __future__ import annotations

import fnmatch

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fns.contain import rbac
from fns.models.snapshot import DenyAssignment
from tests.contain.helpers import KV, RG, SUB_ID
from tests.factories import DA, NOW, pid

# -- patterns ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "action", "expected"),
    [
        ("*", "Microsoft.Storage/storageAccounts/listKeys/action", True),
        ("*/read", "Microsoft.Storage/storageAccounts/read", True),
        ("*/read", "Microsoft.Storage/storageAccounts/listKeys/action", False),
        ("Microsoft.Authorization/*/Write", "Microsoft.Authorization/roleAssignments/write", True),
        (
            "Microsoft.KeyVault/vaults/secrets/*",
            "Microsoft.KeyVault/vaults/secrets/getSecret/action",
            True,
        ),
        ("Microsoft.KeyVault/vaults/secrets/*", "Microsoft.KeyVault/vaults/keys/read", False),
        ("microsoft.storage/*", "Microsoft.Storage/storageAccounts/read", True),
        # Regex metacharacters in patterns are literal.
        ("Microsoft.Storage/storageAccounts/read", "MicrosoftXStorage/storageAccounts/read", False),
        ("a+b", "aab", False),
    ],
)
def test_action_patterns(pattern: str, action: str, expected: bool) -> None:
    assert rbac.action_matches(pattern, action) is expected


_seg = st.text(alphabet="abcAB./", min_size=0, max_size=6)


@given(pattern=st.lists(_seg, min_size=1, max_size=4).map("*".join), action=_seg)
def test_patterns_agree_with_an_independent_glob_oracle(pattern: str, action: str) -> None:
    oracle = fnmatch.fnmatchcase(action.lower(), pattern.lower().replace("[", "[[]"))
    assert rbac.action_matches(pattern, action) is oracle


CONTRIBUTOR = rbac.RoleDefinition(
    "c", "Contributor", ("*",), ("Microsoft.Authorization/*/Write",), (), ()
)


def test_not_actions_subtract_and_planes_never_mix() -> None:
    assert CONTRIBUTOR.permits("Microsoft.Storage/storageAccounts/listKeys/action", data=False)
    assert not CONTRIBUTOR.permits("Microsoft.Authorization/roleAssignments/write", data=False)
    # Contributor's "*" is control plane only.
    blob = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    assert not CONTRIBUTOR.permits(blob, data=True)
    data_role = rbac.RoleDefinition("d", "Data", (), (), ("*",), (blob,))
    assert not data_role.permits(blob, data=True)
    assert not data_role.permits("Microsoft.Storage/storageAccounts/read", data=False)


def test_any_role_permits_everything() -> None:
    assert rbac.ANY.permits("Microsoft.Foo/bar/action", data=False)
    assert rbac.ANY.permits("Microsoft.Foo/bar/action", data=True)


# -- scope relations -------------------------------------------------------------

RG_L = RG.lower()
SUB_L = SUB_ID.lower()
KV_L = KV.lower()


@pytest.mark.parametrize(
    ("scope", "target", "expected"),
    [
        (RG_L, KV_L, "ancestor"),
        (SUB_L, KV_L, "ancestor"),
        (KV_L, KV_L, "self"),
        (KV_L, RG_L, "descendant"),
        ("/", KV_L, "ancestor"),
        ("/providers/microsoft.management/managementgroups/mg1", KV_L, "ancestor"),
        # Segment comparison, never string prefixes.
        (RG_L, RG_L + "-prod", None),
        (RG_L + "-prod", KV_L, None),
        (RG_L[:-1], KV_L, None),
        (f"/subscriptions/{pid(11)}", KV_L, None),
    ],
)
def test_scope_relations(scope: str, target: str, expected: str | None) -> None:
    assert rbac.scope_relation(scope, target) == expected


# -- deny assignments ------------------------------------------------------------

AGENT = pid(100)
GROUP = pid(110)
OTHER = pid(120)
LIST_KEYS = "Microsoft.Storage/storageAccounts/listKeys/action"


def _deny(src: str, scope: str, **kw: object) -> DenyAssignment:
    return DenyAssignment.model_validate(
        {
            "type": "denyAssignment",
            "src": src,
            "dst": scope,
            "deny_assignment_id": f"{scope}/{DA}/{pid(1)}",
            "provenance": {"source_api": "t", "observed_at": NOW.isoformat()},
            **kw,
        }
    )


def test_deny_blocks_matching_action_for_principal_or_group() -> None:
    d = _deny(GROUP, RG_L, actions=["*/action"])
    assert rbac.deny_applies(d, frozenset({AGENT, GROUP}), LIST_KEYS, data=False, at_scope=KV_L)
    assert not rbac.deny_applies(d, frozenset({OTHER}), LIST_KEYS, data=False, at_scope=KV_L)


def test_deny_for_everyone_respects_exclusions() -> None:
    everyone = "00000000-0000-0000-0000-000000000000"
    d = _deny(everyone, RG_L, actions=["*"], excluded_principal_ids=[GROUP])
    assert rbac.deny_applies(d, frozenset({OTHER}), LIST_KEYS, data=False, at_scope=KV_L)
    assert not rbac.deny_applies(d, frozenset({AGENT, GROUP}), LIST_KEYS, data=False, at_scope=KV_L)


def test_deny_not_actions_and_planes() -> None:
    d = _deny(AGENT, RG_L, actions=["*"], not_actions=["*/listKeys/action"])
    assert not rbac.deny_applies(d, frozenset({AGENT}), LIST_KEYS, data=False, at_scope=KV_L)
    assert not rbac.deny_applies(d, frozenset({AGENT}), "x/blobs/read", data=True, at_scope=KV_L)
    d2 = _deny(AGENT, RG_L, data_actions=["*"])
    assert rbac.deny_applies(d2, frozenset({AGENT}), "x/blobs/read", data=True, at_scope=KV_L)


def test_deny_child_scope_flag_and_scope_relations() -> None:
    d = _deny(AGENT, RG_L, actions=["*"], do_not_apply_to_child_scopes=True)
    assert rbac.deny_applies(d, frozenset({AGENT}), LIST_KEYS, data=False, at_scope=RG_L)
    assert not rbac.deny_applies(d, frozenset({AGENT}), LIST_KEYS, data=False, at_scope=KV_L)
    below = _deny(AGENT, KV_L, actions=["*"])
    assert not rbac.deny_applies(below, frozenset({AGENT}), LIST_KEYS, data=False, at_scope=RG_L)
    sibling = _deny(AGENT, RG_L + "-prod", actions=["*"])
    assert not rbac.deny_applies(sibling, frozenset({AGENT}), LIST_KEYS, data=False, at_scope=KV_L)
