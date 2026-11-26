from __future__ import annotations

import copy
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from fns.models.base import CanonicalError, to_canonical
from fns.models.snapshot import Snapshot
from tests.factories import KV, OTHER_TENANT, RG, SP_AGENT, pid, snapshot_dict

BASE_DIGEST = Snapshot.model_validate(snapshot_dict()).digest()


def _snap(d: dict[str, Any]) -> Snapshot:
    return Snapshot.model_validate(d)


def test_round_trip_json() -> None:
    s = _snap(snapshot_dict())
    again = Snapshot.model_validate_json(s.canonical_json())
    assert again == s
    assert again.digest() == s.digest()


def test_canonical_json_is_sorted_and_compact() -> None:
    text = _snap(snapshot_dict()).canonical_json()
    assert ": " not in text and ", " not in text
    assert text.index('"collected_at"') < text.index('"coverage"') < text.index('"edges"')


def test_digest_is_sha256_hex() -> None:
    assert len(BASE_DIGEST) == 64
    int(BASE_DIGEST, 16)


def test_entities_and_edges_are_sorted() -> None:
    s = _snap(snapshot_dict())
    assert [e.id for e in s.entities] == sorted(e.id for e in s.entities)
    keys = [e.sort_key() for e in s.edges]
    assert keys == sorted(keys)


def test_ids_normalized_so_case_does_not_change_digest() -> None:
    d = snapshot_dict()
    for e in d["entities"]:
        e["id"] = e["id"].upper().replace("/SUBSCRIPTIONS/", "/subscriptions/")
    for e in d["edges"]:
        e["src"], e["dst"] = e["src"].upper(), e["dst"].upper()
    assert _snap(d).digest() == BASE_DIGEST


def test_dangling_edge_rejected() -> None:
    d = snapshot_dict()
    d["edges"][0]["dst"] = pid(999)
    with pytest.raises(ValidationError, match="unknown entities"):
        _snap(d)


def test_duplicate_entity_rejected() -> None:
    d = snapshot_dict()
    d["entities"].append(copy.deepcopy(d["entities"][0]))
    with pytest.raises(ValidationError, match="duplicate entity"):
        _snap(d)


def test_duplicate_edge_rejected() -> None:
    d = snapshot_dict()
    d["edges"].append(copy.deepcopy(d["edges"][0]))
    with pytest.raises(ValidationError, match="duplicate edge"):
        _snap(d)


def test_parallel_rbac_edges_with_distinct_assignments_allowed() -> None:
    d = snapshot_dict()
    rbac = next(e for e in d["edges"] if e["type"] == "hasRbacRole")
    twin = copy.deepcopy(rbac)
    twin["assignment_id"] = f"{RG}/providers/Microsoft.Authorization/roleAssignments/{pid(399)}"
    d["edges"].append(twin)
    assert len(_snap(d).edges) == len(snapshot_dict()["edges"]) + 1


@pytest.mark.parametrize(
    "entity",
    [
        {"id": "not-a-guid", "type": "servicePrincipal"},
        {"id": f"/subscriptions/{pid(10)}", "type": "user"},
        {"id": pid(5), "type": "resource"},
        {"id": pid(5), "type": "robot"},
    ],
)
def test_entity_id_must_match_type(entity: dict[str, Any]) -> None:
    d = snapshot_dict()
    d["entities"].append(entity)
    with pytest.raises(ValidationError):
        _snap(d)


def test_float_property_rejected() -> None:
    d = snapshot_dict()
    d["entities"][0]["properties"] = {"weight": 1.5}
    with pytest.raises(ValidationError):
        _snap(d)


def test_canonicalizer_refuses_floats() -> None:
    with pytest.raises(CanonicalError):
        to_canonical({"x": 0.1})


def test_unknown_edge_type_rejected() -> None:
    d = snapshot_dict()
    d["edges"][0]["type"] = "canImpersonate"
    with pytest.raises(ValidationError):
        _snap(d)


def test_mode_is_part_of_digest() -> None:
    d = snapshot_dict()
    d["mode"] = "LIVE"
    assert _snap(d).digest() != BASE_DIGEST


# --- hypothesis -------------------------------------------------------------


@given(data=st.data())
def test_digest_invariant_under_input_order(data: st.DataObject) -> None:
    d = snapshot_dict()
    d["entities"] = data.draw(st.permutations(d["entities"]))
    d["edges"] = data.draw(st.permutations(d["edges"]))
    d["coverage"]["collectors"] = data.draw(st.permutations(d["coverage"]["collectors"]))
    kv = next(e for e in d["entities"] if e["id"] == KV)
    kv["properties"]["tags"] = data.draw(st.permutations(kv["properties"]["tags"]))
    deny = next(e for e in d["edges"] if e["type"] == "denyAssignment")
    deny["actions"] = data.draw(st.permutations(deny["actions"]))
    assert _snap(d).digest() == BASE_DIGEST


aware = st.datetimes(
    min_value=datetime(2000, 1, 1),  # noqa: DTZ001 - hypothesis bounds are naive
    max_value=datetime(2100, 1, 1),  # noqa: DTZ001
    timezones=st.just(UTC),
)


@given(
    collected_at=aware,
    observed=st.lists(aware, min_size=6, max_size=6),
    request_ids=st.lists(st.none() | st.text(max_size=20), min_size=6, max_size=6),
    version=st.text(min_size=1, max_size=20),
    durations=st.lists(st.none() | st.integers(0, 10**9), min_size=2, max_size=2),
)
def test_digest_ignores_volatile_fields(
    collected_at: datetime,
    observed: list[datetime],
    request_ids: list[str | None],
    version: str,
    durations: list[int | None],
) -> None:
    d = snapshot_dict()
    d["collected_at"] = collected_at.isoformat()
    d["collector_version"] = version
    for edge, t, rid in zip(d["edges"], observed, request_ids, strict=True):
        edge["provenance"]["observed_at"] = t.isoformat()
        edge["provenance"]["request_id"] = rid
    for c, ms in zip(d["coverage"]["collectors"], durations, strict=True):
        c["duration_ms"] = ms
    assert _snap(d).digest() == BASE_DIGEST


def _edge(d: dict[str, Any], type_: str) -> dict[str, Any]:
    return next(e for e in d["edges"] if e["type"] == type_)


def _entity(d: dict[str, Any], id_: str) -> dict[str, Any]:
    return next(e for e in d["entities"] if e["id"] == id_)


Mutation = Callable[[dict[str, Any], str], object]


def _drop_kv(d: dict[str, Any]) -> None:
    d["entities"].remove(_entity(d, KV))
    kv = KV.lower()
    d["edges"] = [e for e in d["edges"] if kv not in (e["src"].lower(), e["dst"].lower())]


MUTATIONS: list[tuple[str, Mutation]] = [
    ("tenant", lambda d, s: d.__setitem__("tenant_id", OTHER_TENANT)),
    ("display_name", lambda d, s: _entity(d, SP_AGENT).__setitem__("display_name", "x" + s)),
    ("property", lambda d, s: _entity(d, SP_AGENT)["properties"].__setitem__("note", s)),
    ("tag", lambda d, s: _entity(d, KV)["properties"]["tags"].append("z" + s)),
    ("source_api", lambda d, s: d["edges"][0]["provenance"].__setitem__("source_api", "x" + s)),
    ("condition", lambda d, s: _edge(d, "hasRbacRole").__setitem__("condition", s)),
    ("app_role_value", lambda d, s: _edge(d, "hasAppRole").__setitem__("app_role_value", "x" + s)),
    (
        "deny_action",
        lambda d, s: _edge(d, "denyAssignment").setdefault("not_actions", []).append("x" + s),
    ),
    (
        "child_scopes",
        lambda d, s: _edge(d, "denyAssignment").__setitem__("do_not_apply_to_child_scopes", True),
    ),
    ("status", lambda d, s: d["coverage"]["collectors"][0].__setitem__("status", "failed")),
    ("items", lambda d, s: d["coverage"]["collectors"][0].__setitem__("items", 1000 + len(s))),
    (
        "error_code",
        lambda d, s: d["coverage"]["collectors"][0].setdefault("error_codes", []).append("x" + s),
    ),
    (
        "not_collected",
        lambda d, s: d["coverage"]["not_collected"].append({"surface": "x" + s, "reason": "r"}),
    ),
    ("drop_edge", lambda d, s: d["edges"].pop()),
    ("drop_entity_and_edges", lambda d, s: _drop_kv(d)),
]


@given(
    mutation=st.sampled_from(MUTATIONS),
    text=st.text(alphabet=st.characters(categories=["L", "N"]), min_size=1, max_size=10),
)
def test_digest_changes_on_non_volatile_mutation(mutation: tuple[str, Mutation], text: str) -> None:
    _, mutate = mutation
    d = snapshot_dict()
    mutate(d, text)
    assert _snap(d).digest() != BASE_DIGEST
