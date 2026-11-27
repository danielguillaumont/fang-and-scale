"""``fns prove --after-strike``: D-1 to D-5 as evidence, never looser (D6, 2026-11-27).

The guardrail approved with this change: verdicts may only gain evidence or become
stricter. Every prove golden is re-run with a synthetic after-harden strike run
that observes **every** ``must_not_reach`` item of that golden, once with every
attempt denied and once with every attempt succeeding, and compared with the
recorded baseline (``tests/golden/prove-verdicts.json``):

- all denied: every verdict, coverage, gap, reason and supporting evidence stays
  exactly as recorded; only context is added;
- all succeeded: no finding moves toward ``pass``, and each observed item fails.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.models.assertions import AssertionSet
from fns.models.bundle import EvidenceBundle
from fns.prove.run import check_run
from fns.strike.plan import StrikePlan
from fns.verify.verdict import STRIKE_SOURCE, VERDICT_RANK
from tests.prove.baseline import BASELINE, GOLDENS, decisions, evidence_row, run

BEFORE: dict[str, Any] = json.loads(BASELINE.read_text(encoding="utf-8"))
AT = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)


def _assertions(out: Path) -> AssertionSet:
    (path,) = out.rglob("assertions.json")
    return AssertionSet.model_validate_json(path.read_bytes())


def strike_dir(
    where: Path,
    aset: AssertionSet,
    outcome: str,
    *,
    mode: str | None = None,
    tenant: str | None = None,
    items: list[tuple[str, str]] | None = None,
) -> Path:
    """A finished after-harden strike run observing the given (or every) item."""
    if items is None:
        items = sorted(
            {(a.target, a.operation) for a in aset.assertions if a.item_kind == "must_not_reach"}
        )
    writes = [
        {
            "key": f"D-2/item-{i}",
            "strike": "D-2",
            "request": {
                "operation": "graph:POST /applications/{id}/addPassword",
                "method": "POST",
                "url": f"https://graph.microsoft.com/v1.0/applications/x{i}/addPassword",
            },
            "expect": "denied",
            "observes": [f"{t} {o}"],
        }
        for i, (t, o) in enumerate(items)
    ]
    plan = StrikePlan.model_validate(
        {
            "run_id": "202611271200-guard1",
            "tenant_id": tenant or str(aset.tenant_id).lower(),
            "scope_sha256": "a" * 64,
            "agent_object_id": "00000000-0000-4000-8000-000000000100",
            "created_at": AT.isoformat(),
            "expires_at": AT.replace(hour=13).isoformat(),
            "strikes": ["D-2"],
            "targets": {},
            "pre_state": {},
            "writes": writes,
        }
    )
    status = 403 if outcome == "denied" else 200
    word = "denied" if outcome == "denied" else "unexpected-success"
    where.mkdir(parents=True, exist_ok=True)
    (where / "plan.json").write_text(plan.canonical_json())
    (where / "strike-run.json").write_text(
        json.dumps(
            {
                "mode": mode or aset.mode,
                "run_id": plan.run_id,
                "plan_hash": f"sha256:{plan.plan_hash()}",
                "writes": [{"key": w["key"], "outcome": word, "status": status} for w in writes],
            }
        )
    )
    return where


def prove_with(fixture: Path, out: Path, strikes: Path | None) -> Any:
    args = ["demo", "prove", "--fixture", str(fixture), "--out", str(out)]
    if strikes is not None:
        args += ["--after-strike", str(strikes)]
    return CliRunner().invoke(app, args)


def bundle_of(out: Path) -> EvidenceBundle:
    (path,) = out.rglob("bundle.json")
    return EvidenceBundle.model_validate_json(path.read_bytes())


@pytest.fixture(scope="module", params=sorted(GOLDENS))
def golden(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Any:
    name: str = request.param
    base = tmp_path_factory.mktemp(f"{name}-base")
    run(GOLDENS[name], base)
    aset = _assertions(base)
    results = {}
    for outcome in ("denied", "allowed"):
        d = strike_dir(tmp_path_factory.mktemp(f"{name}-{outcome}-strike"), aset, outcome)
        out = tmp_path_factory.mktemp(f"{name}-{outcome}")
        r = prove_with(GOLDENS[name], out, d)
        assert r.exit_code in {0, 1, 3}, r.output
        results[outcome] = (bundle_of(out), out)
    return name, aset, results


def test_denials_change_no_decision_and_only_add_context(golden: Any) -> None:
    name, aset, results = golden
    bundle, _ = results["denied"]
    before, after = BEFORE[name], decisions(bundle)
    assert after["summary"] == before["summary"]
    for fid, old in before["findings"].items():
        new = after["findings"][fid]
        for key in ("verdict", "coverage", "gap", "reasons", "evidence"):
            assert new[key] == old[key], (name, old["target"], old["operation"], key)
    observed = {(a.target, a.operation) for a in aset.assertions if a.item_kind == "must_not_reach"}
    for f in bundle.findings:
        strike = [e for e in f.evidence if e.source == STRIKE_SOURCE]
        if (f.target, f.operation) in observed:
            assert strike and all(e.role == "context" and e.outcome == "denied" for e in strike)
        else:
            assert strike == []
    assert len(bundle.strike_artifacts) == len(observed)


def test_successes_never_move_a_finding_toward_pass(golden: Any) -> None:
    name, aset, results = golden
    bundle, _ = results["allowed"]
    observed = {(a.target, a.operation) for a in aset.assertions if a.item_kind == "must_not_reach"}
    for f in bundle.findings:
        old = BEFORE[name]["findings"][f.id]
        assert VERDICT_RANK[f.verdict] <= VERDICT_RANK[old["verdict"]], (
            name,
            f.target,
            f.operation,
        )
        if (f.target, f.operation) in observed:
            assert f.verdict == "fail"
            assert f.reasons[0].startswith("an after-harden strike attempt succeeded")
            assert any(e.source == STRIKE_SOURCE and e.role is None for e in f.evidence)
        else:
            assert decisions(bundle)["findings"][f.id]["verdict"] == old["verdict"]
    assert bundle.summary.critical >= BEFORE[name]["summary"]["critical"]
    assert bundle.summary.passed <= BEFORE[name]["summary"]["passed"]


def test_old_supporting_evidence_is_kept(golden: Any) -> None:
    name, _, results = golden
    for outcome in ("denied", "allowed"):
        bundle, _ = results[outcome]
        for f in bundle.findings:
            rows = [evidence_row(e) for e in f.evidence]
            assert all(row in rows for row in BEFORE[name]["findings"][f.id]["evidence"])


def test_the_verifier_check_rederives_the_strike_verdicts(golden: Any) -> None:
    _, _, results = golden
    for outcome in ("denied", "allowed"):
        _, out = results[outcome]
        (run_dir,) = {p.parent for p in out.rglob("bundle.json")}
        code, output = check_run(run_dir)
        assert code == 0, output


# --- refusals and tampering (one golden is enough) -----------------------------------

ONE = GOLDENS["lab-run-3-prove"]


@pytest.fixture(scope="module")
def one_aset(tmp_path_factory: pytest.TempPathFactory) -> AssertionSet:
    base = tmp_path_factory.mktemp("one-base")
    run(ONE, base)
    return _assertions(base)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"mode": "LIVE"}, "cannot be FIXTURE evidence"),
        ({"tenant": "00000000-0000-4000-8000-000000000999"}, "another tenant"),
    ],
)
def test_a_strike_run_that_cannot_count_is_refused(
    tmp_path: Path, one_aset: AssertionSet, change: dict[str, str], message: str
) -> None:
    d = strike_dir(
        tmp_path / "s", one_aset, "denied", mode=change.get("mode"), tenant=change.get("tenant")
    )
    r = prove_with(ONE, tmp_path / "out", d)
    assert r.exit_code == 2 and message in r.output
    assert not list((tmp_path / "out").rglob("assertions.json"))


def test_a_strike_run_for_another_plan_is_refused(tmp_path: Path, one_aset: AssertionSet) -> None:
    d = strike_dir(tmp_path / "s", one_aset, "denied")
    data = json.loads((d / "strike-run.json").read_text())
    data["plan_hash"] = "sha256:" + "0" * 64
    (d / "strike-run.json").write_text(json.dumps(data))
    r = prove_with(ONE, tmp_path / "out", d)
    assert r.exit_code == 2 and "another plan hash" in r.output


def test_non_counting_outcomes_are_dropped(tmp_path: Path, one_aset: AssertionSet) -> None:
    d = strike_dir(tmp_path / "s", one_aset, "denied")
    data = json.loads((d / "strike-run.json").read_text())
    for w, outcome in zip(
        data["writes"], ["gate-denied", "unknown", "failed", "not-run"], strict=False
    ):
        w["outcome"] = outcome
    data["writes"] = data["writes"][:4]
    (d / "strike-run.json").write_text(json.dumps(data))
    r = prove_with(ONE, tmp_path / "out", d)
    assert r.exit_code in {0, 1, 3}, r.output
    assert bundle_of(tmp_path / "out").strike_artifacts == ()


def test_an_unmatched_item_is_recorded_but_attached_to_nothing(
    tmp_path: Path, one_aset: AssertionSet
) -> None:
    d = strike_dir(
        tmp_path / "s", one_aset, "allowed", items=[("application:nobody", "owners/update")]
    )
    r = prove_with(ONE, tmp_path / "out", d)
    assert r.exit_code in {0, 1, 3}, r.output
    b = bundle_of(tmp_path / "out")
    assert [ref.finding_id for ref in b.strike_artifacts] == [None]
    assert decisions(b) == BEFORE["lab-run-3-prove"]  # nothing moved, not even context


def test_a_tampered_strike_artifact_fails_the_check(tmp_path: Path, one_aset: AssertionSet) -> None:
    d = strike_dir(tmp_path / "s", one_aset, "denied")
    assert prove_with(ONE, tmp_path / "out", d).exit_code in {0, 1, 3}
    b = bundle_of(tmp_path / "out")
    (run_dir,) = {p.parent for p in (tmp_path / "out").rglob("bundle.json")}
    art = run_dir / "artifacts" / f"{b.strike_artifacts[0].sha256}.json"
    data = json.loads(art.read_text())
    data["outcome"] = "allowed"
    art.write_text(json.dumps(data))
    code, output = check_run(run_dir)
    assert code == 5 and "EVIDENCE INVALID" in output
