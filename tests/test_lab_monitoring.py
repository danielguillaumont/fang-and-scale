"""``lab/monitoring.tf`` (M4 D2): logging and the detection rules, off by default.

Checked offline against the Terraform text; ``uv run poe lab-check`` validates it
against the provider schema. Nothing here plans or applies.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.harden.detections import TERRAFORM_PARAMETERS, load_rules, terraform_rules

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "lab"
TF = (LAB / "monitoring.tf").read_text(encoding="utf-8")
RULES, _ = load_rules(ROOT / "detections")
runner = CliRunner()

# Diagnostic category -> the Log Analytics table it fills.
CATEGORY_TABLE = {
    "Administrative": "AzureActivity",
    "Security": "AzureActivity",
    "Policy": "AzureActivity",
    "AuditEvent": "AzureDiagnostics",
    "StorageRead": "StorageBlobLogs",
    "StorageWrite": "StorageBlobLogs",
    "AuditLogs": "AuditLogs",
    "ServicePrincipalSignInLogs": "AADServicePrincipalSignInLogs",
}


def _resources(text: str) -> dict[str, str]:
    return {
        f"{m[1]}.{m[2]}": m[3]
        for m in re.finditer(r'^resource "(\w+)" "(\w+)" \{\n(.*?)^\}', text, re.M | re.S)
    }


RESOURCES = _resources(TF)


def test_monitoring_is_off_by_default() -> None:
    variables = (LAB / "variables.tf").read_text(encoding="utf-8")
    block = re.search(r'variable "enable_monitoring" \{(.*?)\n\}', variables, re.S)
    assert block and re.search(r"default\s+= false", block[1])
    assert re.search(r"monitoring_count = var\.enable_monitoring \? 1 : 0", TF)
    assert re.search(r"\n    if var\.enable_monitoring\n", TF)  # detection_rules
    assert "blob_services = var.enable_monitoring ? {" in TF
    gated = {"local.monitoring_count", "local.blob_services", "local.detection_rules"}
    assert len(RESOURCES) == 7
    for name, body in RESOURCES.items():
        first = body.strip().splitlines()[0]
        m = re.fullmatch(r"(count|for_each) = (\S+)", first)
        assert m and m[2] in gated, (name, first)


def test_monitoring_lives_only_in_monitoring_tf() -> None:
    kinds = (
        "azurerm_log_analytics_workspace",
        "azurerm_sentinel_",
        "azurerm_monitor_diagnostic_setting",
        "azurerm_monitor_aad_diagnostic_setting",
    )
    for tf in LAB.glob("*.tf"):
        if tf.name == "monitoring.tf":
            continue
        for name in _resources(tf.read_text(encoding="utf-8")):
            assert not name.startswith(kinds), (tf.name, name)


def _categories(resource: str) -> set[str]:
    return set(re.findall(r'category = "(\w+)"', RESOURCES[resource]))


def test_every_table_a_rule_reads_is_fed() -> None:
    fed = {
        CATEGORY_TABLE[c]
        for body in RESOURCES.values()
        for c in re.findall(r'category = "(\w+)"', body)
    }
    for rule in RULES:
        assert set(rule.tables) <= fed, (rule.id, set(rule.tables) - fed)
    every_category = {
        c for body in RESOURCES.values() for c in re.findall(r'category = "(\w+)"', body)
    }
    assert every_category <= set(CATEGORY_TABLE), every_category - set(CATEGORY_TABLE)


def test_each_source_sends_what_its_rules_read() -> None:
    assert _categories("azurerm_monitor_aad_diagnostic_setting.entra") == {
        "AuditLogs",
        "ServicePrincipalSignInLogs",
    }
    assert _categories("azurerm_monitor_diagnostic_setting.activity_log") == {
        "Administrative",
        "Security",
        "Policy",
    }
    assert (
        '"/subscriptions/${var.subscription_id}"'
        in RESOURCES["azurerm_monitor_diagnostic_setting.activity_log"]
    )
    kv = RESOURCES["azurerm_monitor_diagnostic_setting.key_vault"]
    assert _categories("azurerm_monitor_diagnostic_setting.key_vault") == {"AuditEvent"}
    # The Key Vault rule reads AzureDiagnostics, not the resource-specific table.
    assert 'log_analytics_destination_type = "AzureDiagnostics"' in kv
    assert "azurerm_key_vault.crown_jewels.id" in kv
    assert _categories("azurerm_monitor_diagnostic_setting.blobs") == {
        "StorageRead",
        "StorageWrite",
    }
    for account in ("payroll", "invoices"):
        assert f"azurerm_storage_account.{account}.id}}/blobServices/default" in TF


def test_the_rules_deployed_are_exactly_the_detections_directory() -> None:
    committed = json.loads((LAB / "detections.json").read_text(encoding="utf-8"))
    assert committed == terraform_rules(RULES)
    stems = {p.stem for p in (ROOT / "detections").glob("*.yaml")} - {"EXEMPT"}
    assert set(committed["rules"]) == stems
    rules = RESOURCES["azurerm_sentinel_alert_rule_scheduled.rules"]
    assert "for_each = local.detection_rules" in rules
    assert 'jsondecode(file("${path.module}/detections.json")).rules' in TF
    onboarded = "azurerm_sentinel_log_analytics_workspace_onboarding.lab[0].workspace_id"
    assert f"log_analytics_workspace_id = {onboarded}" in rules


def test_the_committed_file_is_up_to_date_via_the_cli() -> None:
    result = runner.invoke(
        app,
        [
            "detections",
            "export",
            "--terraform",
            str(LAB / "detections.json"),
            "--check",
            "--dir",
            str(ROOT / "detections"),
        ],
    )
    assert result.exit_code == 0, result.output


def test_a_stale_file_fails_the_check(tmp_path: Path) -> None:
    shutil.copytree(ROOT / "detections", tmp_path / "d")
    out = tmp_path / "detections.json"
    args = ["detections", "export", "--dir", str(tmp_path / "d"), "--terraform", str(out)]
    assert runner.invoke(app, [*args, "--check"]).exit_code == 1  # missing
    assert runner.invoke(app, args).exit_code == 0
    assert runner.invoke(app, [*args, "--check"]).exit_code == 0
    rule = tmp_path / "d" / "rbac-assignment-by-workload.yaml"
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("severity: High", "severity: Low"),
        encoding="utf-8",
    )
    stale = runner.invoke(app, [*args, "--check"])
    assert stale.exit_code == 1 and "out of date" in stale.output
    assert runner.invoke(app, ["detections", "export", "--check"]).exit_code == 2


def test_every_parameter_is_filled_at_apply_time() -> None:
    used = {p for r in RULES for p in r.parameters}
    assert used <= TERRAFORM_PARAMETERS
    for p in TERRAFORM_PARAMETERS:
        assert f'"{{{{{p}}}}}", local.{p})' in TF, p
    bad = RULES[0].model_copy(update={"parameters": {"tenant_secret": "x"}})
    with pytest.raises(ValueError, match="cannot fill"):
        terraform_rules([bad])


def test_the_monitored_identities_are_the_strike_plans() -> None:
    block = re.search(r"monitored_identities = jsonencode\(sort\(\[(.*?)\]\)\)", TF, re.S)
    assert block
    named = set(re.findall(r"azuread_service_principal\.(\w+)\.", block[1]))
    assert named == {"billing_agent", "escalation_target"}  # never the scout or the verifier


def test_the_rule_bodies_match_the_sentinel_export() -> None:
    from fns.harden.detections import sentinel_rule

    tf_rules = terraform_rules(RULES)["rules"]
    for rule in RULES:
        params = dict.fromkeys(rule.parameters, '["x"]')
        body = sentinel_rule(rule, params)["properties"]
        tf = tf_rules[rule.id]
        assert tf["display_name"] == body["displayName"]
        assert tf["severity"] == body["severity"] and tf["tactics"] == body["tactics"]
        assert tf["query"].replace("{{monitored_identities}}", '["x"]') == body["query"]
        mapped = [
            {
                "entity_type": m["entityType"],
                "identifier": m["fieldMappings"][0]["identifier"],
                "column_name": m["fieldMappings"][0]["columnName"],
            }
            for m in body["entityMappings"]
        ]
        assert tf["entity_mappings"] == mapped


def test_the_documented_resource_count_matches() -> None:
    singles = [n for n, b in RESOURCES.items() if "count = local.monitoring_count" in b]
    feeds = len(singles) + 2  # one blob setting per storage account
    total = feeds + len(RULES)
    readme = (LAB / "README.md").read_text(encoding="utf-8")
    assert f"the plan adds **{total}** more resources: {feeds} for the workspace" in readme
    assert f'**Built 2026-11-27** (`lab/README.md`, "Monitoring"): {total} more' in (
        ROOT / "docs" / "milestones" / "M4-plan.md"
    ).read_text(encoding="utf-8")
