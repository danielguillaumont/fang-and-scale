from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from fns.fixtures import wellknown as wk
from fns.fixtures.sanitize import (
    GUID_RE,
    PLACEHOLDER_RE,
    REDACTED,
    IdMap,
    sanitize,
    sanitize_text,
)

# Random-looking (but synthetic) GUIDs standing in for real tenant data.
REAL_TENANT = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
REAL_SUB = "6ba7b810-9dad-41d1-80b4-00c04fd430c8"
REAL_SP = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"


def _allowed_guids(text: str) -> list[str]:
    return [
        g
        for g in GUID_RE.findall(text)
        if not (g.lower() in wk.WELL_KNOWN_GUIDS or PLACEHOLDER_RE.match(g.lower()))
    ]


def test_same_guid_maps_to_same_placeholder_across_documents() -> None:
    m = IdMap()
    a = sanitize({"id": REAL_SP, "tenant": REAL_TENANT}, m)
    b = sanitize({"principalId": REAL_SP.upper()}, m)
    assert a["id"] == b["principalId"]
    assert PLACEHOLDER_RE.match(a["id"])
    assert a["tenant"] != a["id"]


def test_well_known_ids_are_kept() -> None:
    m = IdMap()
    body = {
        "appId": wk.MICROSOFT_GRAPH_APP_ID,
        "roleDefinitionId": f"/subscriptions/{REAL_SUB}/providers/Microsoft.Authorization/"
        f"roleDefinitions/{wk.OWNER}",
        "principals": [{"id": wk.EVERYONE}],
    }
    out = sanitize(body, m)
    assert out["appId"] == wk.MICROSOFT_GRAPH_APP_ID
    assert out["roleDefinitionId"].endswith(wk.OWNER)
    assert REAL_SUB not in out["roleDefinitionId"]
    assert out["principals"][0]["id"] == wk.EVERYONE


def test_guids_inside_arm_paths_and_urls_are_replaced() -> None:
    m = IdMap()
    url = (
        f"https://management.azure.com/subscriptions/{REAL_SUB}/providers/"
        f"Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$skiptoken=abc123%3D"
    )
    out = sanitize_text(url, m)
    assert REAL_SUB not in out
    assert "abc123" not in out
    assert "$skiptoken=SKIPTOKEN" in out


def test_guid_keys_are_replaced() -> None:
    m = IdMap()
    out = sanitize({"userAssignedIdentities": {REAL_SP: {"principalId": REAL_SP}}}, m)
    (key,) = out["userAssignedIdentities"].keys()
    assert REAL_SP not in key
    assert out["userAssignedIdentities"][key]["principalId"] == m.guid(REAL_SP)


def test_emails_and_domains_are_rewritten() -> None:
    m = IdMap()
    out = sanitize(
        {
            "userPrincipalName": "alice.smith@contoso.onmicrosoft.com",
            "mail": "Alice.Smith@contoso.com",
            "note": "see contoso.onmicrosoft.com",
            "ext": "bob_contoso.com#EXT#@fabrikam.onmicrosoft.com",
        },
        m,
    )
    text = json.dumps(out)
    assert "contoso" not in text
    assert "fabrikam" not in text
    assert "alice" not in text.lower()
    assert out["userPrincipalName"].endswith("@example.invalid")
    assert out["note"] == "see tenant1.example.invalid"


def test_secrets_and_tokens_are_redacted() -> None:
    m = IdMap()
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLWJ5dGVz"
    out = sanitize(
        {"secretText": "hunter2", "key": 12345, "note": f"Bearer {jwt}", "thumbprint": "AB12"}, m
    )
    assert out["secretText"] == REDACTED
    assert out["key"] == REDACTED
    assert out["thumbprint"] == REDACTED
    assert jwt not in out["note"]


def test_opaque_ids_are_replaced_but_paths_are_not() -> None:
    m = IdMap()
    out = sanitize(
        {
            "value": [
                {"id": "lLHA2T-3TEGYxXlRsKWPj1kDW1W8yxhIlz4YqZgYz3k"},
                {"id": "/subscriptions/x"},
            ]
        },
        m,
    )
    assert out["value"][0]["id"] == "opaque-1"
    assert out["value"][1]["id"] == "/subscriptions/x"


def test_idmap_round_trips_through_disk(tmp_path: Path) -> None:
    m = IdMap()
    first = m.guid(REAL_TENANT)
    m.email("a@contoso.com")
    m.save(tmp_path / "_idmap.json")
    again = IdMap.load(tmp_path / "_idmap.json")
    assert again.guid(REAL_TENANT) == first
    assert again.guid(REAL_SUB) != first
    assert IdMap.load(tmp_path / "missing.json").guids == {}


# --- properties ----------------------------------------------------------------------

guids = st.uuids().map(str) | st.uuids().map(lambda u: str(u).upper())
leaf_text = st.one_of(
    st.text(max_size=20),
    guids,
    st.builds(lambda g, p: f"/subscriptions/{g}/{p}", guids, st.text(max_size=10)),
    st.builds(
        lambda s, d: f"{s}@{d}.com",
        st.from_regex(r"[a-z]{1,8}", fullmatch=True),
        st.from_regex(r"[a-z]{1,8}", fullmatch=True),
    ),
)
keys = st.sampled_from(["id", "name", "principalId", "scope", "displayName", "x"]) | guids
json_values: st.SearchStrategy[Any] = st.recursive(
    st.none() | st.booleans() | st.integers() | leaf_text,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(keys, children, max_size=4),
    max_leaves=25,
)


@given(json_values)
def test_no_guid_survives_except_placeholders_and_well_known(value: Any) -> None:
    out = sanitize(value, IdMap())
    assert _allowed_guids(json.dumps(out)) == []


@given(json_values)
def test_sanitize_is_idempotent(value: Any) -> None:
    m = IdMap()
    once = sanitize(value, m)
    assert sanitize(once, m) == once
    assert sanitize(once, IdMap()) == once


@given(st.lists(st.uuids(), min_size=1, max_size=10, unique=True))
def test_mapping_is_injective(values: list[uuid.UUID]) -> None:
    m = IdMap()
    mapped = [m.guid(str(v)) for v in values]
    kept = [str(v) for v in values if str(v) in wk.WELL_KNOWN_GUIDS]
    assert len(set(mapped)) == len(values) - len(kept) + len(set(kept))
