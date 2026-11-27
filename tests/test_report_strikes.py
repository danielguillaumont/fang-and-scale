"""``fns report --strike --detections``: strikes, detection results, the ladder per finding.

The page is built from FIXTURE files through the real commands (``tests/report_golden.py``)
and compared with ``tests/golden/report-strike-demo.html``. The rest checks what the
page refuses, what it escapes, and that detection results never become evidence.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from fns.cli import app
from fns.models.detection_results import DetectionResults
from fns.models.strike_record import StrikeRunRecord
from fns.report.html import Inputs, check, render_html
from fns.report_cli import load_detections, load_inputs, load_strike
from fns.yamlio import load_yaml
from tests.report_golden import DETECTIONS, GOLDEN, build, main_element

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, dict[str, Path]]:
    return build(tmp_path_factory.mktemp("report-strikes"))


def _inputs(paths: dict[str, Path], **kw: Any) -> Inputs:
    return load_inputs(
        paths["contain"],
        None,
        paths["run"],
        strikes=kw.pop("strikes", [paths["before"], paths["after"]]),
        detections=kw.pop("detections", DETECTIONS),
    )


def test_the_page_matches_the_golden(built: tuple[str, dict[str, Path]]) -> None:
    page, _ = built
    assert main_element(page) == GOLDEN.read_text(encoding="utf-8"), (
        "the report changed: uv run python -m tests.report_golden, and say why in the PR"
    )


def test_it_shows_strikes_detections_and_the_ladder(built: tuple[str, dict[str, Path]]) -> None:
    page, _ = built
    assert page.index('id="coverage"') < page.index('id="strikes"') < page.index('id="detections"')
    assert "S1, S2, S3 (before harden)" in page and "D-1, D-2, D-3, D-4, D-5 (after harden)" in page
    assert page.count("denied, as required") == 5
    assert page.count("succeeded: the capability is real") == 3
    assert "Detections: 2 of 3 fired" in page
    assert "missed: detection-gap" in page and "21 min 30 s" in page
    assert "2 / 2</b><span>strike runs clean" in page
    assert "2 / 3</b><span>detections fired" in page
    # the D-steps' denials reached the findings as context, and the ladder marks them
    assert "<td>context</td><td><code>fns.strike/after-harden</code>" in page
    assert re.search(r'class="rung none" title="observed: nothing; context: denied', page)
    assert "strike observation(s)" in page
    assert "FIXTURE: replayed" in page


def test_the_page_is_still_self_contained(built: tuple[str, dict[str, Path]]) -> None:
    page, _ = built
    assert page.count("<script") == 3  # graph data, Cytoscape, the page's own
    assert not re.search(r"\b(src|href)=\"?https?:", page)
    assert "<link" not in page and "@import" not in page


def test_detections_never_become_evidence(built: tuple[str, dict[str, Path]]) -> None:
    _, paths = built
    with_d = _inputs(paths)
    without = _inputs(paths, detections=None)
    assert with_d.bundle == without.bundle  # nothing reads the detections but the page
    page = render_html(with_d)
    assert "not evidence for any finding" in page
    for rule in ("storage-listkeys-by-workload", "app-credential-added-by-workload"):
        assert (ROOT / "detections" / f"{rule}.yaml").is_file()
        assert f"<code>{rule}</code>" in page


# --- refusals -------------------------------------------------------------------------


def _report(paths: dict[str, Path], tmp: Path, *extra: str) -> Any:
    return runner.invoke(
        app,
        [
            *("report", "--contain", str(paths["contain"]), "--prove", str(paths["run"])),
            *("--out", str(tmp / "r.html"), *extra),
        ],
    )


def test_a_strike_run_from_another_tenant_is_refused(
    built: tuple[str, dict[str, Path]], tmp_path: Path
) -> None:
    _, paths = built
    other = tmp_path / "other"
    other.mkdir()
    plan = json.loads((paths["before"] / "plan.json").read_text())
    plan["tenant_id"] = "00000000-0000-4000-8000-000000000999"
    (other / "plan.json").write_text(json.dumps(plan))
    run = json.loads((paths["before"] / "strike-run.json").read_text())
    from fns.strike.plan import StrikePlan

    run["plan_hash"] = "sha256:" + StrikePlan.model_validate(plan).plan_hash()
    (other / "strike-run.json").write_text(json.dumps(run))
    r = _report(paths, tmp_path, "--strike", str(other))
    assert r.exit_code == 2 and "ran in another tenant" in r.output
    assert not (tmp_path / "r.html").exists()


def test_a_run_that_does_not_match_its_plan_is_refused(
    built: tuple[str, dict[str, Path]], tmp_path: Path
) -> None:
    _, paths = built
    view = load_strike(paths["before"])
    forged = view.run.model_copy(update={"plan_hash": "sha256:" + "0" * 64})
    problems = check(Inputs(_inputs(paths).contain, strikes=(type(view)(view.plan, forged),)))
    assert problems == [f"strike run {view.run.run_id} does not match its plan.json"]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"mode": "LIVE"}, "detections are LIVE but the contain report is FIXTURE"),
        ({"strike_run_id": "202611251200-other1"}, "which is not given"),
    ],
)
def test_detections_that_do_not_fit_are_refused(
    built: tuple[str, dict[str, Path]], change: dict[str, str], message: str
) -> None:
    _, paths = built
    d = load_detections(DETECTIONS).model_copy(update=change)
    inputs = _inputs(paths)
    assert any(
        message in p for p in check(Inputs(inputs.contain, strikes=inputs.strikes, detections=d))
    )


def test_detections_for_a_strike_the_run_did_not_make_are_refused(
    built: tuple[str, dict[str, Path]], tmp_path: Path
) -> None:
    _, paths = built
    data = load_yaml(DETECTIONS)
    data["results"][0]["strike"] = "D-1"
    bad = tmp_path / "d.yaml"
    bad.write_text(json.dumps(data, default=str))
    r = _report(paths, tmp_path, "--strike", str(paths["before"]), "--detections", str(bad))
    assert r.exit_code == 2 and "did not make: ['D-1']" in r.output


def test_detections_without_their_strike_run_are_refused(
    built: tuple[str, dict[str, Path]], tmp_path: Path
) -> None:
    _, paths = built
    r = _report(paths, tmp_path, "--detections", str(DETECTIONS))
    assert r.exit_code == 2 and "which is not given" in r.output


def test_a_malformed_strike_run_is_invalid_input(
    built: tuple[str, dict[str, Path]], tmp_path: Path
) -> None:
    _, paths = built
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "plan.json").write_bytes((paths["before"] / "plan.json").read_bytes())
    run = json.loads((paths["before"] / "strike-run.json").read_text())
    run["writes"][0]["outcome"] = "probably-fine"
    (bad / "strike-run.json").write_text(json.dumps(run))
    r = _report(paths, tmp_path, "--strike", str(bad))
    assert r.exit_code == 2 and "invalid input" in r.output


def test_strike_text_is_escaped(built: tuple[str, dict[str, Path]]) -> None:
    _, paths = built
    view = load_strike(paths["before"])
    checks = [
        c.model_copy(update={"detail": "<img src=x onerror=alert(1)>"})
        for c in view.run.verification
    ]
    run = view.run.model_copy(update={"verification": tuple(checks)})
    inputs = _inputs(paths, detections=None)
    page = render_html(
        Inputs(inputs.contain, bundle=inputs.bundle, strikes=(type(view)(view.plan, run),))
    )
    assert "<img src=x" not in page and "&lt;img src=x onerror=alert(1)&gt;" in page


# --- the two file formats -------------------------------------------------------------


def test_the_engine_output_is_a_valid_strike_run_record(
    built: tuple[str, dict[str, Path]],
) -> None:
    _, paths = built
    for d in (paths["before"], paths["after"]):
        rec = StrikeRunRecord.model_validate_json((d / "strike-run.json").read_bytes())
        assert rec.mode == "FIXTURE" and rec.verified and rec.exit_code == 0


AT = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def _result(**kw: Any) -> dict[str, Any]:
    return {"strike": "S1", "rule": "storage-listkeys-by-workload", "strike_at": AT, "rows": 1} | kw


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (_result(fired=True), "a fired rule needs first_alert_at"),
        (_result(fired=False, first_alert_at=AT), "fired is false"),
        (_result(fired=True, first_alert_at=AT.replace(hour=11)), "before the strike"),
        (_result(fired=True, first_alert_at=AT, rule="Not A Rule"), "pattern"),
        (_result(fired=False, rows=-1), "greater than or equal"),
    ],
)
def test_a_detection_result_must_be_consistent(result: dict[str, Any], message: str) -> None:
    doc = {"version": 1, "mode": "FIXTURE", "strike_run_id": "202611251200-demo01"}
    with pytest.raises(ValidationError, match=message):
        DetectionResults.model_validate(doc | {"source": "t", "results": [result]})


def test_a_strike_and_rule_are_listed_once() -> None:
    doc = {"version": 1, "mode": "FIXTURE", "strike_run_id": "202611251200-demo01", "source": "t"}
    r = _result(fired=False)
    with pytest.raises(ValidationError, match="listed twice"):
        DetectionResults.model_validate(doc | {"results": [r, r]})


def test_states_follow_rows_and_alerts() -> None:
    d = load_detections(DETECTIONS)
    assert [r.state for r in d.results] == ["fired", "fired", "detection-gap"]
    none = DetectionResults.model_validate(
        {
            **{"version": 1, "mode": "FIXTURE", "strike_run_id": "202611251200-demo01"},
            **{"source": "t", "results": [_result(fired=False, rows=0)]},
        }
    )
    assert none.results[0].state == "no-rows"


def test_the_demo_detections_file_says_it_is_hand_written() -> None:
    text = DETECTIONS.read_text(encoding="utf-8")
    assert text.startswith("# FIXTURE: hand-written")
    assert load_detections(DETECTIONS).mode == "FIXTURE"
