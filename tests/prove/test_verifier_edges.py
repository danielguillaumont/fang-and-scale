"""Verifier branches that only subprocess tests reached, now checked in-process.

Coverage, queue item 10. Two groups:
- integrity refusals in ``fns.verify.inputs``: unfinished probes, artifacts that
  name another probe, rung or mode, and strike artifacts;
- the D6 guardrail in ``fns.verify.verdict.with_strikes``, which takes every
  strike observation that is not a counting denial: as a property over real
  findings and any such observations, evidence only grows, a denial changes
  nothing, and no finding moves toward ``pass``. Counting denials (option B) and
  the guardrail around them are in ``test_option_b.py``.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fns.journal.sqlite import SqliteJournal
from fns.models.assertions import AssertionSet, ProbeObservation, StrikeObservation
from fns.models.evidence import Finding
from fns.prove.strikes import record_strikes
from fns.verify.inputs import IntegrityError, load_inputs
from fns.verify.main import build
from fns.verify.verdict import STRIKE_SOURCE, VERDICT_RANK, with_strikes
from tests.prove.helpers import prepared

NOW = datetime(2026, 11, 27, tzinfo=UTC)


def _raw_event(run_dir: Path, run_id: str, key: str, status: str, digest: str | None) -> None:
    """Append a step event the way a tamperer would: straight into the file."""
    conn = sqlite3.connect(run_dir / "journal.sqlite")
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO steps VALUES (?, ?, 'read', 'injected', '2026-11-27T00:00:00Z')",
            (run_id, key),
        )
        conn.execute(
            "INSERT INTO step_events (run_id, step_key, status, at, response_digest) "
            "VALUES (?, ?, ?, '2026-11-27T00:00:01Z', ?)",
            (run_id, key, status, digest),
        )
    conn.close()


def _write_artifact(run_dir: Path, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    (run_dir / "artifacts" / f"{digest}.json").write_bytes(data)
    return digest


def _an_observation(run_dir: Path, aset: AssertionSet) -> tuple[str, dict[str, Any]]:
    inputs = load_inputs(run_dir)
    pid, (obs, _) = sorted(inputs.observations.items())[0]
    return pid, json.loads(obs.canonical_json())


def _strike(aset: AssertionSet, **over: Any) -> StrikeObservation:
    a = next(x for x in aset.assertions if x.item_kind == "must_not_reach")
    data: dict[str, Any] = {
        "version": 1,
        "mode": aset.mode,
        "strike_run_id": "202611271200-abc123",
        "plan_sha256": "a" * 64,
        "write_key": "D-2/add-password",
        "strike": "D-2",
        "target": a.target,
        "operation": a.operation,
        "outcome": "denied",
        "http_status": 403,
        "observed_at": aset.frozen_at,
    }
    return StrikeObservation.model_validate(data | over)


# --- integrity ------------------------------------------------------------------------


def test_no_journal_is_refused(tmp_path: Path) -> None:
    _, run_dir, _, _ = prepared(tmp_path)
    (run_dir / "journal.sqlite").unlink()
    with pytest.raises(IntegrityError, match="no journal"):
        load_inputs(run_dir)


def test_assertions_that_do_not_validate_are_refused(tmp_path: Path) -> None:
    _, run_dir, _, _ = prepared(tmp_path)
    (run_dir / "assertions.json").write_bytes(b'{"version": 99}\n')
    with pytest.raises(IntegrityError, match=r"assertions\.json is invalid"):
        load_inputs(run_dir)


def test_a_journal_without_this_run_is_refused(tmp_path: Path) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    (run_dir / "journal.sqlite").unlink()
    with SqliteJournal(run_dir / "journal.sqlite") as j:
        j.begin_run("another-run", "prove", aset.mode)
    with pytest.raises(IntegrityError, match="no record of this run"):
        load_inputs(run_dir)


@pytest.mark.parametrize("status", ["started", "failed", "needs_reconcile"])
def test_a_probe_whose_last_event_did_not_succeed_is_unfinished_never_observed(
    tmp_path: Path, status: str
) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    pid, _ = _an_observation(run_dir, aset)
    _raw_event(run_dir, aset.run_id, f"probe:{pid}", status, None)
    got = load_inputs(run_dir)
    assert pid in got.unfinished and pid not in got.observations
    bundle, _ = build(got, identity="test", now=NOW)
    (finding,) = [
        f
        for a, f in zip(aset.assertions, bundle.findings, strict=True)
        if any(p.id == pid for p in a.probes)
    ]
    assert finding.verdict != "pass" or any(
        e.rung == "observed" and e.role is None for e in finding.evidence
    )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("probe_id", "f" * 64, "belongs to another probe"),
        ("rung", "the other rung", "different probe kind or rung"),
        ("mode", "LIVE", "different mode"),
    ],
)
def test_an_artifact_that_claims_to_be_something_else_is_refused(
    tmp_path: Path, field: str, value: str, match: str
) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    pid, data = _an_observation(run_dir, aset)
    if field == "rung":
        value = "evaluated" if data["rung"] == "observed" else "observed"
    forged = ProbeObservation.model_validate(data | {field: value})
    digest = _write_artifact(run_dir, forged.file_bytes())
    _raw_event(run_dir, aset.run_id, f"probe:{pid}", "succeeded", digest)
    with pytest.raises(IntegrityError, match=match):
        load_inputs(run_dir)


def test_an_artifact_that_is_not_an_observation_is_refused(tmp_path: Path) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    pid, _ = _an_observation(run_dir, aset)
    digest = _write_artifact(run_dir, b'{"not": "an observation"}\n')
    _raw_event(run_dir, aset.run_id, f"probe:{pid}", "succeeded", digest)
    with pytest.raises(IntegrityError, match="is invalid"):
        load_inputs(run_dir)


# --- strike artifacts -----------------------------------------------------------------


def _with_strike(
    tmp_path: Path, obs: StrikeObservation | None = None
) -> tuple[AssertionSet, Path, StrikeObservation]:
    aset, run_dir, _, _ = prepared(tmp_path)
    o = obs or _strike(aset)
    with SqliteJournal(run_dir / "journal.sqlite") as j:
        record_strikes(j, aset, [o], run_dir)
    return aset, run_dir, o


def test_a_recorded_strike_loads_in_process(tmp_path: Path) -> None:
    _, run_dir, o = _with_strike(tmp_path)
    ((got, sha),) = load_inputs(run_dir).strikes
    assert got == o and sha == hashlib.sha256(o.file_bytes()).hexdigest()


def test_a_tampered_strike_artifact_is_refused(tmp_path: Path) -> None:
    _, run_dir, o = _with_strike(tmp_path)
    path = run_dir / "artifacts" / f"{hashlib.sha256(o.file_bytes()).hexdigest()}.json"
    path.write_bytes(path.read_bytes().replace(b'"denied"', b'"allowed"'))
    with pytest.raises(IntegrityError, match="does not match its digest"):
        load_inputs(run_dir)


@pytest.mark.parametrize(
    ("make", "match"),
    [
        (lambda o: b'{"strike": "D-2"}\n', "strike artifact .* is invalid"),
        (lambda o: o.model_copy(update={"operation": "other/op"}).file_bytes(), "another step"),
        (lambda o: o.model_copy(update={"mode": "LIVE"}).file_bytes(), "different mode"),
    ],
)
def test_a_strike_artifact_that_does_not_fit_its_step_is_refused(
    tmp_path: Path, make: Any, match: str
) -> None:
    aset, run_dir, o = _with_strike(tmp_path)
    digest = _write_artifact(run_dir, make(o))
    _raw_event(run_dir, aset.run_id, o.step_key, "succeeded", digest)
    with pytest.raises(IntegrityError, match=match):
        load_inputs(run_dir)


def test_strike_evidence_journaled_before_the_freeze_is_refused(tmp_path: Path) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    o = _strike(aset)
    digest = _write_artifact(run_dir, o.file_bytes())
    conn = sqlite3.connect(run_dir / "journal.sqlite")
    with conn:
        first = conn.execute("SELECT MIN(id) FROM step_events").fetchone()[0]
        conn.execute(
            "INSERT INTO steps VALUES (?, ?, 'read', 'injected', '2026-11-27T00:00:00Z')",
            (aset.run_id, o.step_key),
        )
        conn.execute(
            "INSERT INTO step_events (id, run_id, step_key, status, at, response_digest) "
            "VALUES (?, ?, ?, 'succeeded', '2026-11-27T00:00:00Z', ?)",
            (first - 1, aset.run_id, o.step_key, digest),
        )
    conn.close()
    with pytest.raises(IntegrityError, match="before the freeze"):
        load_inputs(run_dir)


# --- the guardrail, as a property -----------------------------------------------------


@pytest.fixture(scope="module")
def judged(tmp_path_factory: pytest.TempPathFactory) -> tuple[AssertionSet, list[Finding]]:
    aset, run_dir, _, _ = prepared(tmp_path_factory.mktemp("guardrail"))
    bundle, _ = build(load_inputs(run_dir), identity="test", now=NOW)
    return aset, list(bundle.findings)


ATTEMPT = st.tuples(
    st.sampled_from(["allowed", "denied"]),
    st.sampled_from([200, 201, 204, 400, 403, 404, None]),
    st.integers(min_value=1, max_value=5),
)


@settings(
    max_examples=80, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(index=st.integers(min_value=0, max_value=10_000), attempts=st.lists(ATTEMPT, max_size=4))
def test_strike_evidence_never_loosens_a_verdict(
    judged: tuple[AssertionSet, list[Finding]],
    index: int,
    attempts: list[tuple[str, int | None, int]],
) -> None:
    aset, findings = judged
    f = findings[index % len(findings)]
    strikes = [
        (
            _strike(
                aset,
                target=f.target,
                operation=f.operation,
                outcome=outcome,
                http_status=status,
                write_key=f"D-{n}/attempt",
                strike=f"D-{n}",
            ),
            f"{i}{n}".ljust(64, "0"),
        )
        for i, (outcome, status, n) in enumerate(attempts)
    ]
    new = with_strikes(f, strikes)

    assert VERDICT_RANK[new.verdict] <= VERDICT_RANK[f.verdict]
    # Evidence only grows: every judged item is still there (the model keeps a canonical order).
    kept = list(new.evidence)
    for e in f.evidence:
        kept.remove(e)
    assert all(e.source == STRIKE_SOURCE for e in kept)
    assert len(new.evidence) == len(f.evidence) + len(strikes)
    succeeded = [o for o, _ in strikes if o.outcome == "allowed"]
    if f.item_kind == "must_not_reach" and succeeded:
        assert new.verdict == "fail"
        assert new.reasons[0].startswith("an after-harden strike attempt succeeded")
    else:
        # A denial, or anything on must_still_do, is context: nothing else moves.
        assert (new.verdict, new.coverage, new.gap, new.reasons) == (
            f.verdict,
            f.coverage,
            f.gap,
            f.reasons,
        )
        assert all(e.role == "context" for e in kept)


def test_the_property_saw_both_item_kinds(judged: tuple[AssertionSet, list[Finding]]) -> None:
    _, findings = judged
    assert {f.item_kind for f in findings} == {"must_not_reach", "must_still_do"}
