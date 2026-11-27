"""Detection rules as code: every rule lints clean, the reach model is covered,
and the linter catches each class of mistake."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.harden.coverage import coverage_gaps, coverage_keys
from fns.harden.detections import (
    DetectionRule,
    RuleSamples,
    check_samples,
    lint,
    load_exempt,
    load_rules,
    load_samples,
    minutes,
    render_query,
    sample_gaps,
    sentinel_rule,
)

DETECTIONS = Path(__file__).resolve().parents[2] / "detections"
runner = CliRunner()


def test_every_committed_rule_loads_and_lints_clean() -> None:
    rules, errors = load_rules(DETECTIONS)
    assert errors == []
    assert len(rules) >= 9
    assert len({r.id for r in rules}) == len(rules)
    for r in rules:
        assert lint(r) == [], r.id


def test_the_reach_model_is_covered() -> None:
    rules, _ = load_rules(DETECTIONS)
    assert coverage_gaps(rules, load_exempt(DETECTIONS)) == []
    keys = coverage_keys()
    assert "rule:owner-adds-credential" in keys
    assert "op:resource:listKeys" in keys
    assert "way:kv-control-to-data" in keys


def test_a_new_escalation_rule_without_detection_is_reported() -> None:
    rules, _ = load_rules(DETECTIONS)
    exempt = load_exempt(DETECTIONS)
    trimmed = [r for r in rules if "rule:managed-identity" not in r.covers]
    assert coverage_gaps(trimmed, exempt) == [
        "no detection covers rule:managed-identity (add a rule or an EXEMPT.yaml reason)"
    ]
    assert "EXEMPT.yaml lists unknown key rule:nope" in coverage_gaps(
        rules, {**exempt, "rule:nope": "x"}
    )


def _rule(**changes: Any) -> DetectionRule:
    base: dict[str, Any] = {
        "id": "test-rule",
        "title": "A test rule",
        "description": "Used only by the linter tests.",
        "severity": "Low",
        "tactics": ["Discovery"],
        "covers": ["rule:rbac-write"],
        "tables": ["AzureActivity"],
        "query": (
            "let M = dynamic({{ids}});\nAzureActivity\n"
            "| where Caller in~ (M)\n| project TimeGenerated, Caller"
        ),
        "query_frequency": "PT15M",
        "query_period": "PT1H",
        "entities": {"Account": "Caller"},
        "parameters": {"ids": "object ids"},
    }
    return DetectionRule.model_validate({**base, **changes})


def test_baseline_rule_is_clean() -> None:
    assert lint(_rule()) == []


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"query": "AzureActivity\n| where (Caller == 1\n| project Caller"}, "unclosed bracket"),
        ({"query": "AzureActivity\n| where Caller == 1)\n| project Caller"}, "unbalanced"),
        (
            {"query": 'AzureActivity\n| where Caller == "x\n| project Caller', "parameters": {}},
            "unterminated",
        ),
        ({"tables": ["NoSuchTable"]}, "unknown table"),
        (
            {"query": "SigninLogs\n| project Caller", "parameters": {}},
            "start from one of its declared tables",
        ),
        (
            {"query": "AzureActivity\n| where x == {{other}}\n| project Caller"},
            "undeclared parameter",
        ),
        ({"query": "AzureActivity\n| project Caller"}, "unused parameter"),
        ({"query": "search * | project Caller", "parameters": {}}, "search *"),
        ({"query": "AzureActivity\n| project TimeGenerated", "parameters": {}}, "not projected"),
        ({"query": "AzureActivity\n| where Caller != 1", "parameters": {}}, "projection"),
        ({"query_frequency": "PT2H"}, "must not exceed"),
        ({"query_frequency": "PT1M"}, "below 5 minutes"),
        ({"query_period": "1 hour"}, "ISO 8601"),
    ],
)
def test_linter_catches(changes: dict[str, Any], problem: str) -> None:
    problems = lint(_rule(**changes))
    assert any(problem in p for p in problems), problems


def test_durations() -> None:
    assert minutes("PT15M") == 15
    assert minutes("P1DT2H") == 1560
    with pytest.raises(ValueError):
        minutes("PT")


def test_export_renders_parameters_and_entity_mappings(tmp_path: Path) -> None:
    rules, _ = load_rules(DETECTIONS)
    rbac = next(r for r in rules if r.id == "rbac-assignment-by-workload")
    body = sentinel_rule(rbac, {"monitored_identities": '["00000000-0000-4000-8000-000000000006"]'})
    props = body["properties"]
    assert body["kind"] == "Scheduled"
    assert "{{" not in props["query"]
    assert props["entityMappings"][0]["fieldMappings"][0]["identifier"] == "AadUserId"
    with pytest.raises(ValueError, match="missing parameter"):
        render_query(rbac, {})
    result = runner.invoke(
        app,
        ["detections", "export", "--param", 'monitored_identities=["x"]', "--out", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    files = sorted(tmp_path.glob("*.json"))
    assert len(files) == len(rules)
    assert all(json.loads(f.read_text(encoding="utf-8"))["kind"] == "Scheduled" for f in files)


def test_cli_check(tmp_path: Path) -> None:
    ok = runner.invoke(app, ["detections", "check", "--dir", str(DETECTIONS)])
    assert ok.exit_code == 0, ok.output
    bad = tmp_path / "broken-rule.yaml"
    bad.write_text("id: other-name\ntitle: x\n", encoding="utf-8")
    result = runner.invoke(app, ["detections", "check", "--dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "invalid" in result.output


RULES, _ = load_rules(DETECTIONS)
SAMPLES, SAMPLE_ERRORS = load_samples(DETECTIONS)


def test_every_rule_has_samples_that_alert_and_stay_quiet() -> None:
    assert SAMPLE_ERRORS == []
    assert sample_gaps(RULES, SAMPLES) == []
    for r in RULES:
        cases = SAMPLES[r.id].cases
        assert any(c.alert for c in cases) and not all(c.alert for c in cases), r.id


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_against_its_samples(rule: DetectionRule) -> None:
    assert check_samples(rule, SAMPLES[rule.id]) == []


def _mutated(rule_id: str, old: str, new: str) -> list[str]:
    rule = next(r for r in RULES if r.id == rule_id)
    assert old in rule.query
    return check_samples(
        rule.model_copy(update={"query": rule.query.replace(old, new)}), SAMPLES[rule_id]
    )


def test_the_samples_catch_a_rule_that_fires_on_a_key_delete() -> None:
    problems = _mutated(
        "app-credential-added-by-workload", '| where Change != "delete"' + chr(10), ""
    )
    assert any("S3 undo" in p and "should stay quiet" in p for p in problems), problems


def test_the_samples_catch_a_rule_that_fires_on_a_certificate_sign_in() -> None:
    problems = _mutated("workload-sign-in-with-secret", '"clientAssertion", ', "")
    assert any("clientAssertion" in p and "should stay quiet" in p for p in problems), problems


def test_the_samples_catch_a_rule_that_ignores_failures() -> None:
    problems = _mutated(
        "storage-listkeys-by-workload", 'ActivityStatusValue in~ ("Success", "Succeeded")', "true"
    )
    assert any("after harden" in p for p in problems), problems


def test_a_sample_that_disagrees_is_reported() -> None:
    rule = next(r for r in RULES if r.id == "rbac-assignment-by-workload")
    flipped = RuleSamples.model_validate(
        {
            "params": SAMPLES[rule.id].params,
            "cases": [{**c.model_dump(), "alert": not c.alert} for c in SAMPLES[rule.id].cases],
        }
    )
    problems = check_samples(rule, flipped)
    assert len(problems) == len(flipped.cases)


def test_sample_problems_are_specific() -> None:
    rule = next(r for r in RULES if r.id == "rbac-assignment-by-workload")
    only_alerts = RuleSamples.model_validate(
        {
            "params": {"monitored_identities": "[]"},
            "cases": [{"name": "abc", "alert": True, "row": {}}] * 2,
        }
    )
    problems = check_samples(rule, only_alerts)
    assert "samples: no case that must stay quiet" in problems
    assert any("unknown column" in p for p in problems)
    missing = check_samples(
        rule, RuleSamples.model_validate({"cases": SAMPLES[rule.id].model_dump()["cases"]})
    )
    assert any("missing parameter" in p for p in missing)
    wrong_table = RuleSamples.model_validate(
        {
            "params": SAMPLES[rule.id].params,
            "cases": [{**c.model_dump(), "table": "AuditLogs"} for c in SAMPLES[rule.id].cases],
        }
    )
    assert all("name one of the rule's tables" in p for p in check_samples(rule, wrong_table))
    assert sample_gaps(RULES, {}) and sample_gaps([], SAMPLES)


def test_cli_check_runs_the_samples(tmp_path: Path) -> None:
    import shutil

    shutil.copytree(DETECTIONS, tmp_path / "d")
    sample = tmp_path / "d" / "samples" / "storage-listkeys-by-workload.yaml"
    sample.write_text(
        sample.read_text(encoding="utf-8").replace("alert: false", "alert: true"), encoding="utf-8"
    )
    result = runner.invoke(app, ["detections", "check", "--dir", str(tmp_path / "d")])
    assert result.exit_code == 1
    assert "should alert" in result.output
