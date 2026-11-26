"""Verifier verdict rules (docs/milestones/M3.md), on synthetic frozen assertions."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fns.models.assertions import (
    PROBE_RUNG,
    Assertion,
    PathAssertion,
    ProbeObservation,
    ProbeSpec,
    Thresholds,
    probe_id,
)
from fns.models.evidence import finding_id
from fns.verify.verdict import judge, summarize

T = datetime(2026, 11, 26, tzinfo=UTC)
KV = (
    "/subscriptions/00000000-0000-4000-8000-000000000010/resourcegroups/rg"
    "/providers/microsoft.keyvault/vaults/kv"
)
CONTRACT = "c"


def _spec(fid: str, kind: str, purpose: str, action: str) -> ProbeSpec:
    return ProbeSpec(
        id=probe_id(fid, kind, KV, action),
        kind=kind,  # type: ignore[arg-type]
        rung=PROBE_RUNG[kind],
        purpose=purpose,  # type: ignore[arg-type]
        target=KV,
        action=action,
    )


def _world(
    item_kind: str = "must_not_reach",
    *,
    modeled: str = "allowed",
    path: str | None = "indirect",
    surfaces: tuple[str, ...] = (),
) -> tuple[Assertion, dict[str, ProbeSpec]]:
    """One KV secrets/get item with a direct read, a direct check and (optionally) a path."""
    fid = finding_id(CONTRACT, item_kind, "resource:kv", "secrets/get")
    specs = {
        "read": _spec(fid, "data-read", "direct", "secrets/get"),
        "check": _spec(fid, "arm-permissions", "direct", "getSecret"),
        "hop": _spec(fid, "arm-permissions", "hop", "vaults/write"),
    }
    paths: tuple[PathAssertion, ...] = ()
    pid = "a" * 64
    if path == "indirect":
        paths = (
            PathAssertion(
                path_id=pid, summary="x -> kv-control-to-data", refuted_by=(specs["hop"].id,)
            ),
        )
    elif path == "direct":
        paths = (
            PathAssertion(
                path_id=pid,
                summary="x -> rbac-data-action",
                refuted_by=(specs["read"].id, specs["check"].id),
            ),
        )
    elif path == "escalation":
        paths = (PathAssertion(path_id=pid, summary="x -> owner-adds-credential -> y"),)
    a = Assertion(
        finding_id=fid,
        item_kind=item_kind,  # type: ignore[arg-type]
        target="resource:kv",
        operation="secrets/get",
        modeled_outcome=modeled,  # type: ignore[arg-type]
        modeled_reasons=("model reason",),
        paths=paths,
        probes=tuple(specs.values()),
        open_surfaces=surfaces,
    )
    return a, specs


def _obs(a: Assertion, specs: dict[str, ProbeSpec], **outcomes: str) -> dict[str, Any]:
    out = {}
    for name, outcome in outcomes.items():
        s = specs[name]
        o = ProbeObservation(
            version=1,
            mode="FIXTURE",
            probe_id=s.id,
            finding_id=a.finding_id,
            kind=s.kind,
            rung=s.rung,
            outcome=outcome,  # type: ignore[arg-type]
            observed_at=T,
        )
        out[s.id] = (o, "b" * 64)
    return out


def _judge(a: Assertion, specs: dict[str, ProbeSpec], **outcomes: str) -> Any:
    return judge(a, _obs(a, specs, **outcomes), CONTRACT)


@pytest.mark.parametrize(
    ("path", "surfaces", "outcomes", "verdict", "coverage", "gap"),
    [
        # Observed success always fails, platform-gap when rung 2 disagreed.
        (
            "indirect",
            (),
            {"read": "allowed", "check": "denied"},
            "fail",
            "verified",
            "platform-gap",
        ),
        # Rung 2 lists a granting action and nothing observed: fail at rung 2.
        (None, (), {"check": "allowed"}, "fail", "evaluated-only", None),
        # A denied direct read does not refute an indirect path whose action is allowed.
        ("indirect", (), {"read": "denied", "hop": "allowed"}, "fail", "evaluated-only", None),
        # An escalation path cannot be refuted, whatever the direct probes say.
        ("escalation", (), {"read": "denied", "check": "denied"}, "fail", "modeled-only", None),
        # Every path refuted plus an observed denial: pass, model-gap.
        ("indirect", (), {"read": "denied", "hop": "denied"}, "pass", "verified", "model-gap"),
        ("direct", (), {"read": "denied"}, "pass", "verified", "model-gap"),
        # ...unless a surface that could add reach was not collected (E1).
        (
            "indirect",
            ("pim-eligibility",),
            {"read": "denied", "hop": "denied"},
            "inconclusive",
            "verified",
            None,
        ),
        # Refuted at rung 2 only: no observed denial, so inconclusive.
        ("indirect", (), {"hop": "denied"}, "inconclusive", "evaluated-only", None),
        # Nothing ran: the model's fail stands.
        ("indirect", (), {}, "fail", "modeled-only", None),
    ],
)
def test_must_not_reach_rules(
    path: str | None,
    surfaces: tuple[str, ...],
    outcomes: dict[str, str],
    verdict: str,
    coverage: str,
    gap: str | None,
) -> None:
    a, specs = _world(path=path, surfaces=surfaces, modeled="allowed" if path else "denied")
    f = _judge(a, specs, **outcomes)
    assert (f.verdict, f.coverage, f.gap) == (verdict, coverage, gap), f.reasons


def test_direct_denial_is_attached_as_context_when_a_path_remains() -> None:
    """Approved 2026-11-26: the denial is in the finding, but it settles nothing."""
    a, specs = _world(path="indirect")
    f = _judge(a, specs, read="denied", hop="allowed")
    assert (f.verdict, f.coverage) == ("fail", "evaluated-only")
    assert "denied when probed" in f.reasons[0]
    assert not any(e.rung == "observed" for e in f.supporting)
    (denial,) = [e for e in f.context if e.rung == "observed"]
    assert denial.outcome == "denied" and denial.artifact_digest
    assert {e.rung for e in f.supporting} == {"modeled", "evaluated"}


def test_every_probe_result_ends_up_in_the_finding() -> None:
    a, specs = _world(path="indirect")
    f = _judge(a, specs, read="denied", hop="allowed")
    probed = [e for e in f.evidence if e.rung != "modeled"]
    assert len(probed) == 2  # the denied read and the allowed hop
    assert {(e.rung, e.outcome, e.role) for e in probed} == {
        ("observed", "denied", "context"),
        ("evaluated", "allowed", None),
    }


def test_unreachable_in_model_with_observed_denial_passes_without_gap() -> None:
    a, specs = _world(path=None, modeled="denied")
    f = _judge(a, specs, read="denied", check="denied")
    assert (f.verdict, f.coverage, f.gap) == ("pass", "verified", None)


@pytest.mark.parametrize(
    ("outcomes", "modeled", "verdict", "coverage"),
    [
        ({"read": "allowed"}, "allowed", "pass", "verified"),
        ({"read": "denied", "check": "allowed"}, "allowed", "fail", "verified"),
        ({"check": "denied"}, "allowed", "fail", "evaluated-only"),
        ({"check": "allowed"}, "allowed", "inconclusive", "evaluated-only"),
        ({}, "allowed", "inconclusive", "modeled-only"),
        ({}, "denied", "fail", "modeled-only"),
        ({}, "unknown", "inconclusive", "not-assessed"),
    ],
)
def test_must_still_do_rules(
    outcomes: dict[str, str], modeled: str, verdict: str, coverage: str
) -> None:
    a, specs = _world("must_still_do", modeled=modeled, path=None)
    f = _judge(a, specs, **outcomes)
    assert (f.verdict, f.coverage) == (verdict, coverage), f.reasons


OUTCOME = st.sampled_from(["allowed", "denied", "unknown", "not-run", None])


@given(
    path=st.sampled_from(["indirect", "direct", "escalation", None]),
    modeled=st.sampled_from(["allowed", "denied", "unknown"]),
    surfaces=st.sampled_from([(), ("pim-eligibility",)]),
    read=OUTCOME,
    check=OUTCOME,
    hop=OUTCOME,
)
def test_never_pass_without_observed_denial_and_refuted_paths(
    path: str | None,
    modeled: str,
    surfaces: tuple[str, ...],
    read: str | None,
    check: str | None,
    hop: str | None,
) -> None:
    if path is not None and modeled != "allowed":
        modeled = "allowed"  # paths exist only where the model found reach
    a, specs = _world(path=path, modeled=modeled, surfaces=surfaces)
    outcomes = {k: v for k, v in {"read": read, "check": check, "hop": hop}.items() if v}
    f = _judge(a, specs, **outcomes)
    if f.verdict == "pass":
        assert read == "denied"
        assert not surfaces
        assert path != "escalation"
        if path == "indirect":
            assert hop == "denied"


@given(
    path=st.sampled_from(["indirect", "direct", "escalation", None]),
    read=OUTCOME,
    check=OUTCOME,
    hop=OUTCOME,
    flip=st.sampled_from(["read", "check", "hop"]),
)
def test_more_success_never_turns_fail_into_pass(
    path: str | None, read: str | None, check: str | None, hop: str | None, flip: str
) -> None:
    a, specs = _world(path=path, modeled="allowed" if path else "denied")
    base = {k: v for k, v in {"read": read, "check": check, "hop": hop}.items() if v}
    before = _judge(a, specs, **base)
    after = _judge(a, specs, **{**base, flip: "allowed"})
    if before.verdict == "fail":
        assert after.verdict == "fail"


def test_summary_exit_codes() -> None:
    a, specs = _world(path="indirect")
    fail = _judge(a, specs)
    t = Thresholds(max_critical_reachable=0, max_inconclusive=0, on_inconclusive="fail")
    assert summarize([fail], t).exit_code == 1
    b, sb = _world(path="indirect", surfaces=("pim-eligibility",))
    inc = _judge(b, sb, read="denied", hop="denied")
    assert summarize([inc], t).exit_code == 3
    warn = Thresholds(max_critical_reachable=0, max_inconclusive=0, on_inconclusive="warn")
    s = summarize([inc], warn)
    assert (s.exit_code, s.warning) == (0, "1 inconclusive (max 0)")
