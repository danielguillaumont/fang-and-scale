from __future__ import annotations

from typing import Any, get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from fns.models.evidence import (
    RUNG_ORDER,
    CoverageState,
    Finding,
    Gap,
    ItemKind,
    Outcome,
    Rung,
    Verdict,
    finding_id,
)


def ev(rung: str, outcome: str, source: str = "probe") -> dict[str, Any]:
    return {"rung": rung, "outcome": outcome, "source": source}


def finding(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "contract": "billing-agent-blast-radius",
        "item_kind": "must_not_reach",
        "target": "kv-crown-jewels",
        "operation": "secrets/get",
        "verdict": "inconclusive",
        "coverage": "not-assessed",
        "evidence": [],
        "reasons": ["not assessed in M1"],
    }
    base.update(kw)
    return base


def test_id_computed_and_checked() -> None:
    f = Finding.model_validate(finding())
    assert f.id == finding_id(
        "billing-agent-blast-radius", "must_not_reach", "kv-crown-jewels", "secrets/get"
    )
    with pytest.raises(ValidationError, match="id does not match"):
        Finding.model_validate(finding(id="0" * 64))


def test_pass_on_must_not_reach_requires_observed_denial() -> None:
    ok = finding(verdict="pass", coverage="verified", evidence=[ev("observed", "denied")])
    assert Finding.model_validate(ok).verdict == "pass"

    for evidence, coverage in [
        ([ev("modeled", "denied")], "modeled-only"),
        ([ev("evaluated", "denied")], "evaluated-only"),
        ([ev("logged", "denied")], "verified"),
        ([], "not-assessed"),
    ]:
        with pytest.raises(ValidationError):
            Finding.model_validate(finding(verdict="pass", coverage=coverage, evidence=evidence))


def test_pass_contradicted_by_observed_success_rejected() -> None:
    with pytest.raises(ValidationError, match="contradicted"):
        Finding.model_validate(
            finding(
                verdict="pass",
                coverage="verified",
                evidence=[ev("observed", "denied"), ev("observed", "allowed", "probe2")],
            )
        )


def test_pass_on_must_still_do_requires_observed_or_logged_success() -> None:
    for rung in ("observed", "logged"):
        f = finding(
            item_kind="must_still_do",
            verdict="pass",
            coverage="verified",
            evidence=[ev(rung, "allowed")],
        )
        assert Finding.model_validate(f).verdict == "pass"
    with pytest.raises(ValidationError):
        Finding.model_validate(
            finding(
                item_kind="must_still_do",
                verdict="pass",
                coverage="evaluated-only",
                evidence=[ev("evaluated", "allowed")],
            )
        )


def test_fail_needs_evidence_pointing_the_failing_way() -> None:
    assert (
        Finding.model_validate(
            finding(verdict="fail", coverage="modeled-only", evidence=[ev("modeled", "allowed")])
        ).verdict
        == "fail"
    )
    with pytest.raises(ValidationError):
        Finding.model_validate(
            finding(verdict="fail", coverage="modeled-only", evidence=[ev("modeled", "denied")])
        )


@pytest.mark.parametrize(
    ("evidence", "coverage"),
    [
        ([ev("modeled", "allowed")], "verified"),
        ([ev("observed", "allowed")], "modeled-only"),
        ([ev("evaluated", "allowed"), ev("modeled", "allowed")], "modeled-only"),
        ([ev("observed", "unknown")], "verified"),  # unknown is not a result
    ],
)
def test_coverage_must_match_top_rung(evidence: list[dict[str, Any]], coverage: str) -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(
            finding(verdict="inconclusive", coverage=coverage, evidence=evidence)
        )


def test_no_results_means_inconclusive() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(finding(verdict="fail", coverage="out-of-scope"))
    assert Finding.model_validate(finding(coverage="out-of-scope")).verdict == "inconclusive"


def test_inconclusive_always_constructible_with_matching_coverage() -> None:
    for rung in RUNG_ORDER:
        cov = {"modeled": "modeled-only", "evaluated": "evaluated-only"}.get(rung, "verified")
        Finding.model_validate(finding(coverage=cov, evidence=[ev(rung, "allowed")]))


@pytest.mark.parametrize(
    ("gap", "evidence", "ok"),
    [
        ("model-gap", [ev("modeled", "allowed"), ev("observed", "denied")], True),
        ("model-gap", [ev("observed", "denied")], False),
        ("platform-gap", [ev("evaluated", "denied"), ev("observed", "allowed")], True),
        ("platform-gap", [ev("observed", "allowed")], False),
        ("detection-gap", [ev("observed", "allowed")], True),
        ("detection-gap", [ev("observed", "allowed"), ev("logged", "allowed")], False),
    ],
)
def test_gap_requires_its_disagreement(gap: str, evidence: list[dict[str, Any]], ok: bool) -> None:
    data = finding(verdict="inconclusive", coverage="verified", evidence=evidence, gap=gap)
    if ok:
        assert Finding.model_validate(data).gap == gap
    else:
        with pytest.raises(ValidationError):
            Finding.model_validate(data)


def test_reasons_required() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(finding(reasons=[]))


def test_evidence_sorted_by_rung() -> None:
    f = Finding.model_validate(
        finding(
            coverage="verified",
            evidence=[
                ev("observed", "allowed"),
                ev("modeled", "allowed"),
                ev("evaluated", "denied"),
            ],
        )
    )
    assert [e.rung for e in f.evidence] == ["modeled", "evaluated", "observed"]


# --- hypothesis: whatever validates obeys the rules, restated independently ----

evidence_st = st.builds(
    ev,
    st.sampled_from(get_args(Rung)),
    st.sampled_from(get_args(Outcome)),
    st.sampled_from(["p1", "p2", "p3"]),
)


@given(
    item_kind=st.sampled_from(get_args(ItemKind)),
    verdict=st.sampled_from(get_args(Verdict)),
    coverage=st.sampled_from(get_args(CoverageState)),
    gap=st.none() | st.sampled_from(get_args(Gap)),
    evidence=st.lists(evidence_st, max_size=6),
)
def test_valid_findings_never_overclaim(
    item_kind: str, verdict: str, coverage: str, gap: str | None, evidence: list[dict[str, Any]]
) -> None:
    data = finding(
        item_kind=item_kind, verdict=verdict, coverage=coverage, gap=gap, evidence=evidence
    )
    try:
        f = Finding.model_validate(data)
    except ValidationError:
        return
    pairs = {(e["rung"], e["outcome"]) for e in evidence}
    if f.verdict == "pass" and f.item_kind == "must_not_reach":
        assert ("observed", "denied") in pairs
        assert ("observed", "allowed") not in pairs and ("logged", "allowed") not in pairs
    if f.verdict == "pass" and f.item_kind == "must_still_do":
        assert pairs & {("observed", "allowed"), ("logged", "allowed")}
    results = [e for e in evidence if e["outcome"] in {"allowed", "denied"}]
    if not results:
        assert f.verdict == "inconclusive"
        assert f.coverage in {"not-assessed", "out-of-scope"}
    else:
        top = max(RUNG_ORDER[e["rung"]] for e in results)
        assert f.coverage == (
            "verified" if top >= 3 else {1: "modeled-only", 2: "evaluated-only"}[top]
        )
