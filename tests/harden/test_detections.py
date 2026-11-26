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
    lint,
    load_exempt,
    load_rules,
    minutes,
    render_query,
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
