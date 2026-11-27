"""The KQL subset evaluator used for detection-rule samples (``fns.harden.kql``)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fns.harden import kql


def _run(query: str, *rows: dict[str, Any]) -> list[dict[str, Any]]:
    return kql.run(query, {"T": list(rows)})


def test_where_extend_project() -> None:
    q = 'T | where A == "x" | extend B = strcat(A, "-", tostring(N)) | project B, N'
    assert _run(q, {"A": "x", "N": 1}, {"A": "y", "N": 2}) == [{"B": "x-1", "N": 1}]


def test_let_and_dynamic_literal() -> None:
    q = 'let Ids = dynamic(["AA", "bb"]);\nT | where Id in~ (Ids) | project Id'
    assert _run(q, {"Id": "aa"}, {"Id": "BB"}, {"Id": "cc"}) == [{"Id": "aa"}, {"Id": "BB"}]
    assert _run('let Ids = dynamic(["AA"]); T | where Id in (Ids) | project Id', {"Id": "aa"}) == []


def test_negated_in() -> None:
    q = 'T | where K !in~ ("clientAssertion", "managedIdentity") | project K'
    rows = ({"K": "CLIENTASSERTION"}, {"K": "clientSecret"}, {"K": None})
    assert _run(q, *rows) == [{"K": "clientSecret"}]


def test_null_comparisons_are_not_true() -> None:
    # A missing dynamic member is null; == and != on null are null, so where drops both.
    rows: tuple[dict[str, Any], ...] = ({"D": {"a": "x"}}, {"D": {}})
    assert _run('T | where tostring(D.a) != "x" | project D', *rows) == [{"D": {}}]
    assert _run('T | where D.a != "x" | project D', *rows) == []
    assert _run('T | where not(D.a == "x") | project D', *rows) == []


def test_a_missing_column_is_an_error_not_null() -> None:
    with pytest.raises(kql.KqlError, match="unknown column"):
        _run('T | where Missing == "x" | project A', {"A": 1})


@pytest.mark.parametrize(
    "query",
    [
        "T | join (U) on A",
        "T | summarize count() by A",
        "T | summarize N = count() by A",
        "T | mv-expand X = A",
        "search *",
        "T | where A matches regex 'x'",
        "T | where parse_url(A) == 1",
        "T | take 5",
    ],
)
def test_anything_else_is_refused(query: str) -> None:
    with pytest.raises(kql.KqlError):
        _run(query, {"A": "x"})


def test_has_is_a_term_match_and_contains_a_substring() -> None:
    dash = chr(0x2013)  # the en dash Entra puts in the operation name
    op = f"Update application {dash} Certificates and secrets management"
    rows = ({"S": op}, {"S": "xsecrets"})
    assert _run('T | where S has "secrets management" | project S', *rows) == [rows[0]]
    assert _run('T | where S has "SECRETS" | project S', *rows) == [rows[0]]
    assert _run('T | where S contains "secrets" | project S', *rows) == list(rows)
    assert _run('T | where S !has "secrets" | project S', *rows) == [rows[1]]


def test_between_and_numbers() -> None:
    rows = ({"C": 199}, {"C": 200}, {"C": 299}, {"C": 300})
    assert _run("T | where C between (200 .. 299) | project C", *rows) == [{"C": 200}, {"C": 299}]
    with pytest.raises(kql.KqlError, match="numbers"):
        _run('T | where C > "1" | project C', {"C": 2})


def test_comparing_a_string_with_a_number_is_an_error() -> None:
    # ResultType is a string in AADServicePrincipalSignInLogs; a sample must say so.
    with pytest.raises(kql.KqlError, match="cannot compare"):
        _run('T | where R == "0" | project R', {"R": 0})


def test_paths_indexes_and_tostring_of_dynamic() -> None:
    row = {"T": [{"id": "a", "p": [{"n": 1}]}, {"id": "b"}]}
    q = (
        'T | extend A = tostring(T[0].id), B = tostring(T[1]["id"]), C = T[5].id, '
        "D = tostring(T[0].p) | project A, B, C, D"
    )
    assert _run(q, row) == [{"A": "a", "B": "b", "C": None, "D": '[{"n":1}]'}]


def test_mv_apply_with_summarize_keeps_rows_with_empty_arrays() -> None:
    q = (
        "T | mv-apply P = Props on (summarize "
        'Old = sumif(array_length(todynamic(tostring(P.old))), tostring(P.name) == "K"), '
        'New = sumif(array_length(todynamic(tostring(P.new))), tostring(P.name) == "K"), '
        "Names = make_set(tostring(P.name)), N = count()) "
        '| extend Change = case(New > Old, "add", New < Old, "delete", "unknown") '
        "| project Id, Change, Names, N"
    )
    rows = (
        {
            "Id": 1,
            "Props": [
                {"name": "K", "old": "[]", "new": '["a"]'},
                {"name": "X", "old": "", "new": ""},
            ],
        },
        {"Id": 2, "Props": [{"name": "K", "old": '["a","b"]', "new": '["b"]'}]},
        {"Id": 3, "Props": []},
        {"Id": 4, "Props": None},
        {"Id": 5, "Props": [{"name": "K", "old": "not json", "new": "nor this"}]},
    )
    assert _run(q, *rows) == [
        {"Id": 1, "Change": "add", "Names": ["K", "X"], "N": 2},
        {"Id": 2, "Change": "delete", "Names": ["K"], "N": 1},
        {"Id": 3, "Change": "unknown", "Names": [], "N": 0},
        {"Id": 4, "Change": "unknown", "Names": [], "N": 0},
        {"Id": 5, "Change": "unknown", "Names": ["K"], "N": 1},
    ]


def test_strings_comments_and_escapes() -> None:
    # KQL text: T // a comment | where nothing
    #           | where S == 'it\'s' or S == "say \"hi\"" | project S
    q = "T // a comment | where nothing\n"
    q += r"""| where S == 'it\'s' or S == "say \"hi\"" | project S"""
    assert _run(q, {"S": "it's"}, {"S": 'say "hi"'}, {"S": "x"}) == [
        {"S": "it's"},
        {"S": 'say "hi"'},
    ]


def test_iff_isnotempty_and_case() -> None:
    q = 'T | project By = iff(isnotempty(tostring(I.user.id)), "user", "app"), E = isempty(I.app)'
    assert _run(q, {"I": {"user": {"id": "u"}}}, {"I": {"app": {"id": "a"}}}) == [
        {"By": "user", "E": True},
        {"By": "app", "E": False},
    ]
    with pytest.raises(kql.KqlError, match="case"):
        _run("T | project X = case(true, 1) ", {"A": 1})


def test_malformed_queries() -> None:
    for bad in (
        "T | where (A == 1",
        "T | project",
        "T | extend A",
        "let X = 1 T",
        "T | where A == 1 )",
    ):
        with pytest.raises(kql.KqlError):
            _run(bad, {"A": 1})
    with pytest.raises(kql.KqlError, match="no rows given"):
        kql.run("U | project A", {"T": []})


# --- properties ---------------------------------------------------------------------

TEXT = st.text(alphabet="abcXYZ -_é0", max_size=12)


@given(TEXT, TEXT)
def test_eq_is_exact_and_eq_tilde_ignores_case(a: str, b: str) -> None:
    rows = ({"A": a, "B": b},)
    assert bool(_run("T | where A == B | project A", *rows)) == (a == b)
    assert bool(_run("T | where A =~ B | project A", *rows)) == (a.lower() == b.lower())
    assert bool(_run("T | where A != B | project A", *rows)) == (a != b)


@given(TEXT, TEXT)
def test_has_implies_contains(a: str, b: str) -> None:
    rows = ({"A": a, "B": b},)
    if _run("T | where A has B | project A", *rows):
        assert _run("T | where A contains B | project A", *rows)


@given(st.lists(TEXT, max_size=5), TEXT)
def test_in_tilde_is_case_insensitive_membership(values: list[str], probe: str) -> None:
    q = f"let L = dynamic({kql.tostring(values)}); T | where A in~ (L) | project A"
    assert bool(_run(q, {"A": probe})) == (probe.lower() in {v.lower() for v in values})


@given(st.booleans() | st.none(), st.booleans() | st.none())
def test_three_valued_logic(a: bool | None, b: bool | None) -> None:
    def expect_and() -> bool | None:
        if a is False or b is False:
            return False
        return True if (a, b) == (True, True) else None

    def expect_or() -> bool | None:
        if a is True or b is True:
            return True
        return False if (a, b) == (False, False) else None

    rows = ({"A": a, "B": b},)
    assert bool(_run("T | where A and B | project A", *rows)) == (expect_and() is True)
    assert bool(_run("T | where A or B | project A", *rows)) == (expect_or() is True)
