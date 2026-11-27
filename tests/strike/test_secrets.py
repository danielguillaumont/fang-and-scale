"""Secret stripping: what the transport removes before any other code sees it."""

from __future__ import annotations

import copy
import json
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from fns.strike.secrets import REMOVED, SECRET_FIELDS, SecretHolder, secret_values, strip_secrets

LIST_KEYS = {
    "keys": [
        {"keyName": "key1", "value": "FAKE-SECRET-1", "permissions": "FULL"},
        {"keyName": "key2", "value": "FAKE-SECRET-2", "permissions": "FULL"},
    ]
}
ADD_PASSWORD = {
    "keyId": "00000000-0000-4000-8000-000000000700",
    "displayName": "fns-strike-run-1",
    "secretText": "FAKE-SECRET-3",
}
TOKEN = {"token_type": "Bearer", "access_token": "FAKE-SECRET-4", "expires_in": 3599}


def test_list_keys_answer_keeps_nothing_secret() -> None:
    clean, found = strip_secrets(LIST_KEYS)
    assert clean == {"keys": REMOVED}
    assert {"FAKE-SECRET-1", "FAKE-SECRET-2"} <= set(secret_values(found))
    assert "FAKE-SECRET" not in json.dumps(clean)


def test_add_password_keeps_the_key_id_only() -> None:
    clean, found = strip_secrets(ADD_PASSWORD)
    assert clean["keyId"] == ADD_PASSWORD["keyId"]
    assert clean["secretText"] == REMOVED
    assert found == {"/secretText": "FAKE-SECRET-3"}


def test_token_answer() -> None:
    clean, found = strip_secrets(TOKEN)
    assert clean["access_token"] == REMOVED and clean["expires_in"] == 3599
    assert secret_values(found) == ["FAKE-SECRET-4"]


def test_nested_and_in_lists() -> None:
    body = {"value": [{"inner": {"password": "FAKE-SECRET-5"}}, {"ok": 1}]}
    clean, found = strip_secrets(body)
    assert clean == {"value": [{"inner": {"password": REMOVED}}, {"ok": 1}]}
    assert found == {"/value/0/inner/password": "FAKE-SECRET-5"}


def test_never_mutates_the_input() -> None:
    body = copy.deepcopy(LIST_KEYS)
    strip_secrets(body)
    assert body == LIST_KEYS


def test_holder_never_prints_a_value() -> None:
    holder = SecretHolder()
    holder.put("S3/add-password", {"/secretText": "FAKE-SECRET-6"})
    for text in (repr(holder), str(holder), f"{holder}", f"{holder!r}"):
        assert "FAKE-SECRET" not in text
        assert "/secretText" in text
    assert holder.get("S3/add-password", "/secretText") == "FAKE-SECRET-6"
    assert holder.count() == 1 and holder.count_for("S3/add-password") == 1
    holder.wipe()
    assert holder.count() == 0 and holder.get("S3/add-password", "/secretText") is None


json_leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=8))
keys = st.one_of(st.sampled_from(sorted(SECRET_FIELDS)), st.text(min_size=1, max_size=6))


def _tree() -> st.SearchStrategy[Any]:
    return st.recursive(
        json_leaf,
        lambda inner: st.one_of(
            st.lists(inner, max_size=4), st.dictionaries(keys, inner, max_size=4)
        ),
        max_leaves=20,
    )


def _planted(value: Any, marker: str) -> Any:
    """Put ``marker`` under every secret key, wherever the tree has one."""
    if isinstance(value, dict):
        return {
            k: (marker if k in SECRET_FIELDS else _planted(v, marker)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_planted(v, marker) for v in value]
    return value


@given(_tree())
def test_no_planted_secret_survives(tree: Any) -> None:
    marker = "PLANTED-7f3a"
    planted = _planted(tree, marker)
    clean, found = strip_secrets(planted)
    assert marker not in json.dumps(clean)
    assert all(v == marker for v in secret_values(found) if "PLANTED" in v)
    again, more = strip_secrets(clean)
    assert again == clean and all(v == REMOVED for v in more.values())
