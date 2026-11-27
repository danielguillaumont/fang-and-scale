"""Write-gate refusals that the rule table did not reach (coverage, queue item 10).

Each case is a refusal branch in ``fns.scope.writes`` that no test exercised.
They are pinned here with their exact reason, so a refactor cannot turn one into
an allow, or into an internal error, without a failing test.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any
from urllib.parse import quote

import pytest

from fns.scope.gate import Denied, DenyReason, Gate, WriteRequest
from fns.scope.writes import (
    WriteRefusedError,
    canonical_body,
    check_lab_object,
    hard_deny,
    marker_roles,
)
from tests.factories import TENANT
from tests.scope.test_gate_writes import _ready
from tests.scope.writekit import (
    APP_ESC,
    APP_PATCH,
    ARM,
    ASSIGN,
    GRAPH,
    LIST_KEYS,
    PAYROLL,
    STORAGE_V,
    VAULT_WRITE,
    app_json,
    valid,
    write_gate,
)

LAB_TAGS = {"project": "fang-and-scale", "purpose": "lab"}


def _nested(depth: int) -> Any:
    value: Any = "x"
    for _ in range(depth):
        value = {"a": value}
    return value


def _encoded(path: str, times: int) -> str:
    for _ in range(times):
        path = quote(path, safe="")
    return path


def _denied(gate: Gate, r: WriteRequest) -> Denied:
    d = gate.check_write(r)
    assert isinstance(d, Denied), "allowed"
    return d


@pytest.mark.parametrize(
    ("name", "op", "change", "reason", "detail"),
    [
        (
            "body nested 40 deep",
            VAULT_WRITE,
            {"body": {"tags": _nested(40)}},
            DenyReason.BAD_BODY,
            "nests too deeply",
        ),
        (
            "a body key that is not a string",
            VAULT_WRITE,
            {"body": {"tags": {1: "x"}}},
            DenyReason.BAD_BODY,
            "keys are strings",
        ),
        (
            "a tag name over 512 characters",
            VAULT_WRITE,
            {"body": {"tags": {**LAB_TAGS, "k" * 513: "v"}}},
            DenyReason.BAD_BODY,
            "too long",
        ),
        (
            "a tag value over 256 characters",
            VAULT_WRITE,
            {"body": {"tags": {**LAB_TAGS, "k": "v" * 257}}},
            DenyReason.BAD_BODY,
            "too long",
        ),
        (
            "appRoles that is not a list",
            APP_PATCH,
            {"body": {"appRoles": "x"}},
            DenyReason.BAD_BODY,
            "appRoles is a list",
        ),
        (
            "an ARM path with an extra segment",
            LIST_KEYS,
            {"url": f"{ARM}{PAYROLL}/extra/listKeys?{STORAGE_V}"},
            DenyReason.BAD_URL,
            "not an ARM resource path",
        ),
        (
            "an ARM path without a subscription GUID",
            LIST_KEYS,
            {"url": f"{ARM}/subscriptions/x/listKeys?{STORAGE_V}"},
            DenyReason.BAD_URL,
            "not an ARM resource path",
        ),
        (
            "a child resource of a target",
            LIST_KEYS,
            {"url": f"{ARM}{PAYROLL}/blobServices/default/listKeys?{STORAGE_V}"},
            DenyReason.STRIKE_TARGET_NOT_ALLOWED,
            "not a strike target",
        ),
    ],
)
def test_refusal(
    name: str, op: str, change: dict[str, Any], reason: DenyReason, detail: str
) -> None:
    gate, r = _ready(op)
    d = _denied(gate, replace(r, **change))
    assert d.reason is reason, f"{name}: {d.reason} ({d.detail})"
    assert detail in d.detail, name


@pytest.mark.parametrize("times", range(1, 17))
def test_a_denied_path_encoded_up_to_16_times_is_hard_denied(times: int) -> None:
    gate, r = _ready(ASSIGN)
    path = _encoded("/roleManagement/directory/roleAssignments", times)
    d = _denied(gate, replace(r, url=f"{GRAPH}/{path}"))
    assert d.reason is DenyReason.HARD_DENY


@pytest.mark.parametrize("times", [17, 18, 24])
def test_past_16_encodings_the_strict_url_rule_still_refuses(times: int) -> None:
    # The denylist decodes at most 16 rounds; the form match never decodes and
    # refuses any "%" at all. Two layers, so an extra round of encoding gains nothing.
    gate, r = _ready(ASSIGN)
    path = _encoded("/roleManagement/directory/roleAssignments", times)
    assert hard_deny(f"{GRAPH}/{path}", None) is None
    d = _denied(gate, replace(r, url=f"{GRAPH}/{path}"))
    assert d.reason is DenyReason.BAD_URL


def test_an_application_that_has_not_passed_the_live_check_is_refused() -> None:
    gate, _, _ = write_gate(confirm=False)
    d = _denied(gate, valid(APP_PATCH))
    assert d.reason is DenyReason.LAB_CHECK_FAILED and "live lab check" in d.detail


def test_canonical_body_refuses_deep_nesting_without_recursion_error() -> None:
    with pytest.raises(WriteRefusedError, match="nests too deeply") as exc:
        canonical_body(_nested(10_000))
    assert exc.value.kind == "body"


@pytest.mark.parametrize("body", ["x", None, [], {"appRoles": "x"}, {"appRoles": None}])
def test_marker_roles_of_a_body_without_a_roles_list_is_empty(body: Any) -> None:
    assert marker_roles(body) == frozenset()


@pytest.mark.parametrize(
    ("observed", "detail"),
    [
        ("not json", "needs the object's JSON"),
        ([app_json(APP_ESC)], "needs the object's JSON"),
        ({**app_json(APP_ESC), "id": 200}, "not the target"),
        ({**app_json(APP_ESC), "id": None}, "not the target"),
        ({**app_json(APP_ESC), "appId": 5}, "appId is missing"),
    ],
)
def test_check_lab_object_refuses_malformed_reads(observed: Any, detail: str) -> None:
    good = app_json(APP_ESC)
    with pytest.raises(WriteRefusedError, match=detail) as exc:
        check_lab_object(
            "graph-application",
            uuid.UUID(APP_ESC),
            good["displayName"],
            observed,
            tenant_id=uuid.UUID(TENANT),
            application=None,
        )
    assert exc.value.kind == "lab-check"
