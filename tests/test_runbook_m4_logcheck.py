"""The M4 log path check runbook (``docs/runbooks/m4-log-path-check.md``).

The owner runs it by hand on the lab tenant (decision D1). These checks keep the
text to what was asked:

- nothing real filled in: every ID comes from a Terraform output;
- exactly one deliberate audit event and one service principal sign-in, by the
  read-only scout, with a certificate valid for at most a day;
- queries whose output is safe to paste;
- everything it creates removed again, ending in ``lab-down``;
- a plan count that matches the lab's ``.tf`` files.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "runbooks" / "m4-log-path-check.md"
TEXT = RUNBOOK.read_text(encoding="utf-8")
BLOCKS = re.findall(r"```powershell\n(.*?)```", TEXT, re.S)
COMMANDS = [
    line.split("#", 1)[0].strip()
    for block in BLOCKS
    for line in block.splitlines()
    if line.split("#", 1)[0].strip()
]
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _section(heading: str) -> str:
    start = TEXT.index(heading)
    nxt = TEXT.find("\n## ", start + len(heading))
    return TEXT[start : nxt if nxt != -1 else len(TEXT)]


def test_every_terraform_output_it_reads_exists() -> None:
    outputs = set(
        re.findall(r'^output "([a-z_]+)"', (ROOT / "lab" / "outputs.tf").read_text(), re.M)
    )
    used = set(re.findall(r"terraform -chdir=lab output -(?:raw|json) ([a-z_]+)", TEXT))
    assert used, "the runbook should take its IDs from terraform output"
    assert used <= outputs, used - outputs


def test_nothing_real_is_filled_in() -> None:
    assert GUID.findall(TEXT) == []
    assert re.findall(r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}", TEXT) == []
    assert "<TENANT_ID>" in TEXT and "<SUBSCRIPTION_ID>" in TEXT


def _resource_blocks() -> dict[str, str]:
    blocks: dict[str, str] = {}
    for tf in sorted((ROOT / "lab").glob("*.tf")):
        text = tf.read_text(encoding="utf-8")
        for m in re.finditer(r'^resource "(\w+)" "(\w+)" \{\n(.*?)^\}', text, re.M | re.S):
            blocks[f"{m[1]}.{m[2]}"] = m[3]
    return blocks


def test_the_expected_plan_count_matches_the_lab() -> None:
    blocks = _resource_blocks()
    multi = {
        name for name, body in blocks.items() if re.search(r"^\s+(count|for_each) =", body, re.M)
    }
    # With the defaults: the budget (no email) and the GitHub OIDC credential (no repository)
    # are off; the scout has 4 Graph grants (Directory.Read.All on); runner_blobs covers 2
    # accounts. A new count or for_each resource fails here, so this runbook gets updated.
    off = {
        "time_static.budget_start",
        "azurerm_consumption_budget_subscription.lab",
        "azuread_application_federated_identity_credential.scout_github",
        # lab/monitoring.tf (enable_monitoring = false by default)
        "azurerm_log_analytics_workspace.lab",
        "azurerm_sentinel_log_analytics_workspace_onboarding.lab",
        "azurerm_monitor_diagnostic_setting.activity_log",
        "azurerm_monitor_diagnostic_setting.key_vault",
        "azurerm_monitor_diagnostic_setting.blobs",
        "azurerm_monitor_aad_diagnostic_setting.entra",
        "azurerm_sentinel_alert_rule_scheduled.rules",
        # lab/scope.tf (enable_strikes = false by default)
        "time_offset.strike_expiry",
    }
    copies = {
        "azuread_app_role_assignment.scout_graph": 4,
        "azurerm_role_assignment.runner_blobs": 2,
    }
    assert multi == off | set(copies)
    expected = len(blocks) - len(off) + sum(n - 1 for n in copies.values())
    assert f"**{expected} to add, 0 to change, 0 to destroy**" in TEXT
    assert f"**{expected + 2} to add**" in TEXT  # with budget_alert_email


def test_both_categories_are_requested_and_both_tables_queried() -> None:
    step4 = _section("## 4. Send both Entra categories to it")
    assert 'category = "AuditLogs"' in step4
    assert 'category = "ServicePrincipalSignInLogs"' in step4
    assert "microsoft.aadiam/diagnosticSettings/fns-logcheck" in step4
    step8 = _section("## 8. Check that both arrived")
    assert "AuditLogs" in step8 and "AADServicePrincipalSignInLogs" in step8


def test_one_audit_event_and_one_sign_in_by_the_read_only_scout() -> None:
    resets = [c for c in COMMANDS if "az ad app credential reset" in c]
    assert len(resets) == 1 and "--id $scoutId" in resets[0] and "--create-cert" in resets[0]
    assert "AddHours(23)" in _section("## 5. Cause one harmless audit event")
    logins = [c for c in COMMANDS if c.startswith("az login --service-principal")]
    assert len(logins) == 1 and "--username $scoutId" in logins[0]
    assert "client_id" in TEXT and "output -json scout" in TEXT
    assert "billing_agent" not in TEXT  # the escalation-capable identity is not used


def test_only_sign_in_commands_run_as_the_scout() -> None:
    step6 = _section("## 6. Cause one service principal sign-in")
    block = re.findall(r"```powershell\n(.*?)```", step6, re.S)[0]
    lines = [ln.split("#", 1)[0].strip() for ln in block.splitlines()]
    start = lines.index("$env:AZURE_CONFIG_DIR = $scoutDir")
    end = lines.index("Remove-Item Env:AZURE_CONFIG_DIR")
    as_scout = [ln for ln in lines[start + 1 : end] if ln]
    allowed = ("az login --service-principal", "az account show", "$signInAt =", "az logout")
    assert as_scout and all(ln.startswith(allowed) for ln in as_scout), as_scout


def test_the_certificate_list_is_checked_empty_before_and_after() -> None:
    step5 = _section("## 5. Cause one harmless audit event")
    assert step5.count("# must print nothing") == 1 and "must print nothing" in step5
    step7 = _section("## 7. Delete the scout certificate")
    assert "az ad app credential delete" in step7 and "# must print nothing" in step7


def test_the_queries_return_nothing_identifying() -> None:
    queries = [c for c in COMMANDS if re.match(r"\$q\w+ = ", c)]
    assert len(queries) == 3
    for q in queries:
        for column in (
            "IPAddress",
            "UserPrincipalName",
            "AppId",
            "ServicePrincipalId",
            "CorrelationId",
            "TenantId",
            "Location",
        ):
            assert column not in q, (column, q)


def test_everything_it_creates_is_removed_and_the_lab_torn_down() -> None:
    step9 = _section("## 9. Remove the diagnostic setting and the workspace")
    assert "az rest --method delete --url $diag" in step9
    assert "workspace delete -g rg-fns-logcheck -n law-fns-logcheck --force true" in step9
    assert "az group delete -n rg-fns-logcheck" in step9
    assert "uv run poe lab-down" in _section("## 10. Tear down the lab")
    emergency = _section("## Emergency cleanup")
    for needed in (
        "diagnosticSettings/fns-logcheck",
        "az group delete -n rg-fns-logcheck",
        "lab-down",
        "credential delete",
    ):
        assert needed in emergency, needed


def test_the_tool_only_reads() -> None:
    fns = [c for c in COMMANDS if "fns " in c and c.startswith("uv run fns")]
    assert fns == ["uv run fns scope check scope.lab.yaml"]
    assert "fns strike" not in TEXT and "harden --apply" not in TEXT


def test_the_m4_plan_and_readme_point_here() -> None:
    for doc in ("docs/milestones/M4-plan.md", "README.md"):
        assert "docs/runbooks/m4-log-path-check.md" in (ROOT / doc).read_text(encoding="utf-8"), doc


def test_commands_that_prompt_are_pasted_alone() -> None:
    # Pasting more lines after lab-up or lab-down answers Terraform's yes prompt (FINDINGS).
    prompting = [b for b in BLOCKS if re.search(r"poe lab-(up|down)\b", b)]
    assert len(prompting) >= 3  # step 2, step 10 and the emergency cleanup
    for block in prompting:
        lines = [ln.split("#", 1)[0].strip() for ln in block.splitlines()]
        assert [ln for ln in lines if ln] in (["uv run poe lab-up"], ["uv run poe lab-down"]), block


def test_the_2026_11_27_corrections() -> None:
    assert "az group show --ids" not in TEXT
    assert "az group show -n rg-fns-lab" in TEXT
    step8 = _section("## 8. Check that both arrived")
    assert "`ClientCredentialType` = **`clientAssertion`**" in step8
    assert "`ClientCredentialType` = `Certificate`" not in TEXT
    audit = next(c for c in COMMANDS if c.startswith("$qAudit = "))
    assert "modifiedProperties" in audit
    assert "Change = case(After > Before, 'add', After < Before, 'delete'" in audit
    assert "**two** rows" in step8
    assert "Run on 2026-11-27: passed." in TEXT
