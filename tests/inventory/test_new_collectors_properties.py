"""Property tests for the 2026-11-28 collectors: hostile responses never crash a
parser, never leak a value, and every item is either kept or reported.

The responses are what Graph could return in shape, not what it does return:
types swapped, fields missing, extra fields with secrets in them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from fns.adapters.azure import graph
from fns.contain.federation import GITHUB_ISSUER, TOKEN_EXCHANGE_AUDIENCE, classify
from fns.inventory.builder import SnapshotBuilder
from fns.models.snapshot import Provenance
from tests.factories import pid

PROV = Provenance(source_api="test", observed_at=datetime(2026, 11, 28, tzinfo=UTC))
OWNER = pid(200)
TENANT = pid(1)
SECRET = "s3cr3t-VALUE-never-kept"  # noqa: S105 - a marker, not a credential

scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.text(max_size=20),
    st.sampled_from([pid(301), pid(302), "2026-06-01T00:00:00Z", SECRET]),
)
value = st.recursive(scalar, lambda inner: st.lists(inner, max_size=3), max_leaves=6)


def _item(keys: list[str]) -> st.SearchStrategy[dict[str, Any]]:
    return st.dictionaries(st.sampled_from(keys), value, max_size=len(keys))


CRED_KEYS = [
    "keyId",
    "displayName",
    "type",
    "usage",
    "startDateTime",
    "endDateTime",
    "key",
    "customKeyIdentifier",
    "hint",
    "secretText",
]
FIC_KEYS = [
    "id",
    "name",
    "issuer",
    "subject",
    "audiences",
    "description",
    "claimsMatchingExpression",
]
GROUP_KEYS = ["id", "displayName", "isAssignableToRole", "@odata.type", "securityEnabled"]


def _snapshot_text(b: SnapshotBuilder) -> str:
    from fns.models.snapshot import SnapshotCoverage

    snap = b.build(
        mode="FIXTURE",
        tenant_id=TENANT,
        collected_at=PROV.observed_at,
        collector_version="test",
        coverage=SnapshotCoverage(collectors=(), not_collected=()),
    )
    return snap.canonical_json()


@settings(max_examples=150)
@given(st.lists(_item(CRED_KEYS), max_size=4), st.lists(_item(CRED_KEYS), max_size=4))
def test_credentials_never_crash_or_keep_a_value(
    keys: list[dict[str, Any]], pws: list[dict[str, Any]]
) -> None:
    for row in (*keys, *pws):
        for secret_field in ("key", "secretText", "hint", "customKeyIdentifier"):
            row.setdefault(secret_field, SECRET)
    b = SnapshotBuilder()
    body = {"id": OWNER, "keyCredentials": keys, "passwordCredentials": pws}
    count, errors = graph.parse_credentials(b, OWNER, body, PROV)
    assert count + errors.count("bad-item") == len(keys) + len(pws)
    assert SECRET not in _snapshot_text(b)


@settings(max_examples=150)
@given(st.lists(st.one_of(_item(FIC_KEYS), value), max_size=5))
def test_federated_credentials_never_crash_and_account_for_every_item(items: list[Any]) -> None:
    b = SnapshotBuilder()
    dicts = [i for i in items if isinstance(i, dict)]
    errors = graph.parse_federated_credentials(b, OWNER, dicts, PROV)
    kept = len(dicts) - len(errors)
    assert 0 <= kept <= len(dicts)
    assert set(errors) <= {"bad-item"}


@settings(max_examples=150)
@given(st.lists(_item(GROUP_KEYS), max_size=5))
def test_transitive_groups_never_crash_and_only_keep_a_stated_boolean(
    items: list[dict[str, Any]],
) -> None:
    b = SnapshotBuilder()
    member = pid(100)
    b.entity(member, "servicePrincipal", display_name="sp-agent")
    errors = graph.parse_transitive_groups(b, member, items, PROV)
    assert set(errors) <= {"bad-item"}
    text = _snapshot_text(b)
    if not any(isinstance(i.get("isAssignableToRole"), bool) for i in items):
        assert "isAssignableToRole" not in text


subjects = st.one_of(
    st.none(),
    st.text(max_size=40),
    st.sampled_from(
        [
            "repo:contoso/billing:pull_request",
            "repo:contoso/billing:ref:refs/heads/main",
            "repo:contoso/billing:environment:production",
            "repo:contoso/billing:pull-request",
            pid(400),
        ]
    ),
)
issuers = st.one_of(
    st.text(max_size=40),
    st.sampled_from(
        [GITHUB_ISSUER, f"https://login.microsoftonline.com/{TENANT}/v2.0", "https://x.example"]
    ),
)


@given(issuers, subjects, st.lists(st.text(max_size=30), max_size=3))
def test_classify_is_total_and_deterministic(
    issuer: str, subject: str | None, audiences: list[str]
) -> None:
    a = classify(issuer, subject, tuple(audiences), TENANT)
    b = classify(issuer, subject, tuple(audiences), TENANT)
    assert a == b
    assert a.severity in {"high", "medium", "unknown"}
    assert a.reasons and a.party
    if a.kind.startswith("github-"):
        assert issuer == GITHUB_ISSUER
    if a.kind == "github-pull-request":
        assert subject is not None and subject.endswith(":pull_request")


@given(st.text(min_size=1, max_size=20).filter(lambda s: ":" not in s))
def test_only_the_github_issuer_ever_gets_a_github_kind(repo: str) -> None:
    subject = f"repo:{repo}:pull_request"
    fake = classify("https://token.actions.githubusercontent.com.evil", subject, (), TENANT)
    assert not fake.kind.startswith("github-")
    real = classify(GITHUB_ISSUER, subject, (TOKEN_EXCHANGE_AUDIENCE,), TENANT)
    assert real.kind == "github-pull-request"


# Every Graph list parser: one malformed object is a "bad-item" (the collector is then
# partial), never an exception that aborts the scout. Found by the test above: a group
# whose displayName was not a string escaped as a pydantic ValidationError.
ANY_KEYS = [
    "id",
    "displayName",
    "appId",
    "appRoleId",
    "principalId",
    "resourceId",
    "roleDefinitionId",
    "directoryScopeId",
    "servicePrincipalType",
    "appOwnerOrganizationId",
    "appRoles",
    "isBuiltIn",
    "templateId",
    "rolePermissions",
    "isAssignableToRole",
]
odata = st.sampled_from(
    ["#microsoft.graph.group", "#microsoft.graph.servicePrincipal", "#microsoft.graph.user"]
)
hostile = st.lists(
    st.fixed_dictionaries({"@odata.type": odata}, optional=dict.fromkeys(ANY_KEYS, value)),
    max_size=4,
)

PARSERS: dict[str, Any] = {
    "service_principals": lambda b, items: graph.parse_service_principals(b, items)[1],
    "applications": lambda b, items: graph.parse_applications(b, items, {}, PROV),
    "owners": lambda b, items: graph.parse_owners(b, OWNER, items, PROV),
    "member_of": lambda b, items: graph.parse_member_of(b, pid(100), items, PROV),
    "transitive_groups": lambda b, items: graph.parse_transitive_groups(b, pid(100), items, PROV),
    "app_role_assignments": lambda b, items: graph.parse_app_role_assignments(b, items, {}, PROV),
    "directory_role_definitions": lambda b, items: graph.parse_directory_role_definitions(b, items),
    "directory_role_assignments": lambda b, items: graph.parse_directory_role_assignments(
        b, items, PROV
    ),
    "directory_role_eligibility": lambda b, items: graph.parse_directory_role_eligibility(
        b, items, PROV
    )[1],
}


@settings(max_examples=60)
@given(st.sampled_from(sorted(PARSERS)), hostile)
def test_no_graph_list_parser_lets_a_malformed_object_escape(
    name: str, items: list[dict[str, Any]]
) -> None:
    b = SnapshotBuilder()
    b.entity(pid(100), "servicePrincipal", display_name="sp-agent")
    errors = PARSERS[name](b, items)
    assert all(isinstance(e, str) for e in errors)
    _snapshot_text(b)  # whatever was kept still builds a valid snapshot


def test_a_group_with_a_non_string_name_is_a_bad_item_not_a_crash() -> None:
    """The case hypothesis found (2026-11-28), pinned for every parser that met it."""
    group = {"@odata.type": "#microsoft.graph.group", "id": pid(301), "displayName": []}
    for parse in (graph.parse_transitive_groups, graph.parse_member_of):
        b = SnapshotBuilder()
        assert parse(b, pid(100), [group], PROV) == ["bad-item"]
    assert graph.parse_owners(SnapshotBuilder(), OWNER, [group], PROV) == ["bad-item"]
