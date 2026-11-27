"""The M4 live runbook (``docs/runbooks/m4-live-run.md``), sessions A to D.

The owner runs it by hand on the lab tenant. These checks keep the text to what
the plans approved (``docs/milestones/M4-plan.md``, ``M4-strikes-plan.md``):

- nothing real filled in: every ID comes from a Terraform output or ``az``;
- every ``fns`` command and option it uses exists;
- the tool writes only through ``fns strike run``, only S1 to S4 and D-1 to D-5,
  each with an approved hash and two separate CLI profiles; S4 right after S3,
  in the same run (approved 2026-11-27);
- every certificate lasts at most a day and is deleted again;
- one query per strike, whose output names nothing identifying, and rules that
  exist in ``detections/``;
- an emergency cleanup for every write a strike can make, the S4 marker
  assignment included;
- plan counts that match the lab's ``.tf`` files;
- commands that prompt are pasted alone.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any

import click
import pytest
import typer

from fns.cli import app
from tests.test_runbook_m4_logcheck import _resource_blocks

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "runbooks" / "m4-live-run.md"
TEXT = RUNBOOK.read_text(encoding="utf-8")
BLOCKS = re.findall(r"```powershell\n(.*?)```", TEXT, re.S)


def _code(line: str) -> str:
    """The command without a trailing ``# comment`` (``#`` inside quotes is kept)."""
    return re.sub(r"\s+#\s.*$", "", line).strip()


COMMANDS = [_code(ln) for block in BLOCKS for ln in block.splitlines() if _code(ln)]
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
PROMPTS = re.compile(r"poe lab-(up|down)\b|terraform -chdir=lab apply")


def _section(heading: str) -> str:
    start = TEXT.index(heading)
    nxt = re.search(r"\n#{2,3} ", TEXT[start + len(heading) :])
    end = start + len(heading) + nxt.start() if nxt else len(TEXT)
    return TEXT[start:end]


def _session(name: str) -> str:
    start = TEXT.index(f"## {name}")
    nxt = TEXT.find("\n## ", start + 4)
    return TEXT[start : nxt if nxt != -1 else len(TEXT)]


# --- nothing real ---------------------------------------------------------------------


def test_nothing_real_is_filled_in() -> None:
    assert GUID.findall(TEXT) == []
    assert re.findall(r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}", TEXT) == []
    assert "<TENANT_ID>" in TEXT and "<SUBSCRIPTION_ID>" in TEXT
    assert not re.search(r"\b[0-9a-f]{64}\b", TEXT)  # no plan hash typed in


def test_every_terraform_output_it_reads_exists() -> None:
    outputs = set(
        re.findall(r'^output "([a-z_]+)"', (ROOT / "lab" / "outputs.tf").read_text(), re.M)
    )
    used = set(re.findall(r"terraform -chdir=lab output -(?:raw|json) ([a-z_]+)", TEXT))
    assert {"billing_agent", "scout", "resources", "monitoring", "identities"} <= used
    assert used <= outputs, used - outputs


# --- fns commands ---------------------------------------------------------------------


def _fns_lines() -> list[str]:
    return [c for c in COMMANDS if c.startswith("uv run fns ")]


def _resolve(argv: list[str]) -> tuple[Any, list[str]]:
    cmd: Any = typer.main.get_command(app)
    rest = list(argv)
    while hasattr(cmd, "commands") and rest and not rest[0].startswith("-"):
        sub = cmd.get_command(click.Context(cmd), rest[0])
        assert sub is not None, argv
        cmd, rest = sub, rest[1:]
    return cmd, rest


def test_every_fns_command_and_option_exists() -> None:
    assert _fns_lines()
    for line in _fns_lines():
        argv = shlex.split(line.removeprefix("uv run fns "), posix=False)
        cmd, rest = _resolve(argv)
        known = {o for p in cmd.params for o in getattr(p, "opts", [])}
        for flag in (a for a in rest if a.startswith("--")):
            assert flag in known, (line, flag)


def test_the_tool_writes_only_through_strike_run() -> None:
    verbs = {" ".join(shlex.split(c, posix=False)[3:5]) for c in _fns_lines()}
    allowed = {
        "scope check",
        "scout --scope",
        "detections check",
        "detections export",
        "record (Join-Path",
        "contain --contract",
        "harden --contract",
        "strike plan",
        "strike run",
        "strike cleanup",
        "prove --contract",
    }
    assert verbs <= allowed, verbs - allowed
    assert "--apply" not in TEXT.replace("`harden --apply` is not built", "")
    assert "git apply harden.diff" in TEXT


def test_strikes_are_s1_to_s4_then_d1_to_d5() -> None:
    plans = [c for c in _fns_lines() if "strike plan" in c]
    assert [re.search(r"--strikes (\S+)", c)[1] for c in plans] == [  # type: ignore[index]
        "S1,S2,S3,S4",  # S4 only right after S3, in the same run
        "D-1,D-2,D-3,D-4,D-5",
    ]
    runs = [c for c in _fns_lines() if re.search(r"strike (run|cleanup)", c)]
    assert len(runs) == 3
    for c in runs:
        assert "--approve $hash" in c and "--plan $plan" in c
        assert "--agent-config $agentDir" in c and "--scout-config $scoutDir" in c
    assert '$scoutDir = Join-Path $env:TEMP "fns-m4-scout-az"' in TEXT
    assert '$agentDir = Join-Path $env:TEMP "fns-m4-agent-az"' in TEXT


def test_s4_is_reviewed_with_its_conditions() -> None:
    c3, c4 = _section("### C3."), _section("### C4.")
    assert "Expected: five writes, all `allowed`" in c3
    assert (
        "| `S4/token` | `POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`" in c3
    )
    assert "**no secret**" in c3 and "right after `S4/token`" in c3
    assert "`appRoleId` the marker" in c3 and "as the escalated identity" in c3
    assert "| S4/assign       | allowed | succeeded | 201    | 204      |" in c4
    assert "only its `oid` and `roles` claims" in c4
    assert "`needs-emergency-cleanup`" in c4 and 'step 2, "S4"' in c4
    c1 = _section("### C1.")
    assert "`random_uuid.strike_marker[0]`" in c1 and '"Grants nothing"' in c1


def test_the_approval_is_typed_by_the_owner_after_review() -> None:
    for session in ("Session C", "Session D"):
        text = _session(session)
        assert '$hash = "<the 64 hex characters after plan sha256:>"' in text
        review = text.index(".writes | ForEach-Object")
        assert review < text.index("$hash = ") < text.index("uv run fns strike run")


def test_prove_after_harden_carries_the_strike_evidence() -> None:
    (line,) = [c for c in _fns_lines() if " prove " in c]
    assert "--live" in line and "--after-strike $dRun" in line
    assert "--record fixtures/lab-run-5" in line
    assert "exit 3" in _section("### D7.")  # the guardrail keeps the app items inconclusive


# --- identities and certificates ------------------------------------------------------


def test_every_certificate_lasts_at_most_a_day_and_none_is_a_secret() -> None:
    resets = [c for c in COMMANDS if "az ad app credential reset" in c]
    assert len(resets) == 6  # A3 scout, B2 agent, C2 both, D1 scout, D6 agent
    for c in resets:
        assert "--create-cert" in c and "--end-date $end" in c and "--append" in c
        assert "--display-name fns-m4-" in c
    ends = [c for c in COMMANDS if c.startswith("$end = ")]
    assert ends and all("AddHours(23)" in c for c in ends)


def test_every_certificate_is_deleted_again() -> None:
    for heading in ("### A4.", "### B2.", "### C5.", "### 3. Delete the certificates"):
        assert "credential delete" in _section(heading) and "--cert" in _section(heading)
    assert "Run C5 again" in _section("### D8.")


def test_credential_lists_are_checked_empty_before_each_reset() -> None:
    for block in BLOCKS:
        if "credential reset" not in block:
            continue
        before = block[: block.index("credential reset")]
        assert "# must print nothing" in before, block[:200]


def test_only_the_listed_commands_run_signed_in_as_the_agent() -> None:
    allowed = (
        "az login --service-principal",
        "az account show",
        "az storage blob download",
        "az storage blob upload",
        "uv run fns prove",
        "$LASTEXITCODE",
        "az logout",
    )
    seen = 0
    for block in BLOCKS:
        as_agent = False
        for line in (_code(x) for x in block.splitlines()):
            if line == "$env:AZURE_CONFIG_DIR = $agentDir":
                as_agent, seen = True, seen + 1
                continue
            if line.startswith(("Remove-Item Env:AZURE_CONFIG_DIR", "$env:AZURE_CONFIG_DIR = ")):
                as_agent = False
            if as_agent and line:
                assert line.startswith(allowed), line
    assert seen == 4  # B2, C2, D6, and D7 (which reuses D6's profile)


# --- detections (D5) ------------------------------------------------------------------

IDENTIFYING = (
    "Caller",
    "IPAddress",
    "CallerIpAddress",
    "UserPrincipalName",
    "AppId",
    "ServicePrincipalId",
    "CorrelationId",
    "TenantId",
    "_ResourceId",
    "ResourceId",
    "InitiatingAppId",
    "TargetObjectId",
)


def _queries() -> dict[str, str]:
    return dict(re.findall(r'^\$(q\w+) = "(.*)"$', "\n".join(COMMANDS), re.M))


def test_one_query_per_strike_and_one_for_alerts() -> None:
    q = _queries()
    assert {"qS1", "qS2", "qS3", "qS4", "qAlerts"} <= set(q)
    assert "Add app role assignment to service principal" in q["qS4"]
    assert "Remove app role assignment from service principal" in q["qS4"]
    assert "LISTKEYS/ACTION" in q["qS1"] and "REGENERATEKEY/ACTION" in q["qS1"]
    assert "VAULTS/WRITE" in q["qS2"]
    assert "app-escalation-target" in q["qS3"] and "Change = case(" in q["qS3"]
    assert q["qAlerts"].startswith("SecurityAlert")


@pytest.mark.parametrize("name", ["qS1", "qS2", "qS3", "qS4", "qAlerts"])
def test_query_output_names_nothing_identifying(name: str) -> None:
    query = _queries()[name]
    output = query[query.rindex("| project ") :] if "| project " in query else query
    if "summarize" in output and "| project " not in output:
        output = query[query.rindex("| summarize ") :]
    for column in IDENTIFYING:
        assert column not in output, (name, column)
    if name in ("qS3", "qS4"):  # only whether an app or a user did it, never which one
        assert (
            "By = iff(isnotempty(tostring(InitiatedBy.app.servicePrincipalId)), 'app', 'user')"
            in output
        )


def test_the_expected_rules_exist_with_their_display_names() -> None:
    rules = json.loads((ROOT / "lab" / "detections.json").read_text(encoding="utf-8"))["rules"]
    table = _section("### C6.")
    for rule in (
        "storage-listkeys-by-workload",
        "keyvault-control-plane-write-by-workload",
        "app-credential-added-by-workload",
        "app-role-assignment-by-workload",
    ):
        assert f"`{rule}`" in table
        assert f'"{rules[rule]["display_name"]}"' in table
        assert (ROOT / "detections" / f"{rule}.yaml").is_file()
    assert "Microsoft.Storage" not in table  # names, not resource IDs


# --- plan counts ----------------------------------------------------------------------


def test_the_monitoring_plan_count_matches_lab_monitoring_tf() -> None:
    text = (ROOT / "lab" / "monitoring.tf").read_text(encoding="utf-8")
    names = re.findall(r'^resource "(\w+)" "(\w+)"', text, re.M)
    rules = len(json.loads((ROOT / "lab" / "detections.json").read_text())["rules"])
    blobs = 2  # payroll and invoices
    expected = len(names) - 2 + blobs + rules
    assert ("azurerm_monitor_diagnostic_setting", "blobs") in names
    assert ("azurerm_sentinel_alert_rule_scheduled", "rules") in names
    assert f"**The plan must be {expected} to add, 0 to change, 0 to destroy**" in TEXT
    assert f"$mon.rules.Count                                 # must print {rules}" in TEXT


def test_the_base_plan_count_is_the_log_path_checks() -> None:
    logcheck = (ROOT / "docs" / "runbooks" / "m4-log-path-check.md").read_text(encoding="utf-8")
    m = re.search(r"\*\*(\d+) to add, 0 to change, 0 to destroy\*\*", logcheck)
    assert m is not None
    assert f"**{m[1]} to add, 0 to change, 0 to destroy** with the defaults" in TEXT
    assert len(_resource_blocks()) > int(m[1]) // 2  # sanity: the helper read the lab


def test_strikes_add_the_expiry_and_the_marker_and_rerender_the_scope() -> None:
    c1 = _section("### C1.")
    assert "`time_offset.strike_expiry[0]` and `random_uuid.strike_marker[0]`" in c1
    assert "`azuread_application.escalation_target` is updated in place" in c1
    assert "`local_file.scope`" in c1
    assert "**3 to add, 1\nto change, 1 to destroy**" in c1
    blocks = _resource_blocks()
    assert "random_uuid.strike_marker" in blocks and "time_offset.strike_expiry" in blocks
    d5 = _section("### D5.")
    assert 'terraform -chdir=lab apply "-replace=time_offset.strike_expiry[0]"' in d5
    readme = (ROOT / "lab" / "README.md").read_text(encoding="utf-8")
    assert '"-replace=time_offset.strike_expiry[0]"' in readme


def test_harden_removes_exactly_the_two_grants() -> None:
    d2 = _section("### D2.")
    for grant in (
        "azurerm_role_assignment.billing_agent_rg_contributor",
        "azuread_app_role_assignment.billing_agent_owned_by",
    ):
        assert grant in d2
        kind, name = grant.split(".")
        assert f"{kind}.{name}" in _resource_blocks()
    assert "**The plan must be 0 to add, 0 to change, 2 to destroy**" in _section("### D3.")


def test_commands_that_prompt_are_pasted_alone() -> None:
    prompting = [b for b in BLOCKS if PROMPTS.search(b)]
    assert len(prompting) >= 7  # A2, B1, C1, D3, D5, Teardown, Emergency cleanup
    for block in prompting:
        lines = [_code(ln) for ln in block.splitlines() if _code(ln)]
        assert len(lines) == 1 and PROMPTS.search(lines[0]), block


# --- emergency cleanup ----------------------------------------------------------------


def test_every_strike_write_has_a_manual_undo() -> None:
    emergency = _session("Emergency cleanup")
    for needed in (
        "uv run fns strike cleanup",
        "starts_with(displayName, 'fns-strike-')",  # S3, D-1 to D-3
        "az ad app owner remove",  # D-4, D-5
        '--operation Delete --tags "fns-strike=$v"',  # S2
        "--key primary",  # S1
        "--key secondary",
        "uv run poe lab-down",
        "from strike_events",
        "appRoles[?value=='fns.strike.marker'].id",  # S4
        "az rest --method delete --url",
        "value[?appRoleId=='$marker']",
    ):
        assert needed in emergency, needed
    assert "It **cannot** undo `S4/assign`" in emergency


def test_the_only_az_rest_writes_are_the_s4_emergency_deletes() -> None:
    writes = [c for c in COMMANDS if c.startswith("az rest") and "--method get" not in c]
    assert writes and all(c.startswith("az rest --method delete --url") for c in writes)
    assert all("/appRoleAssignedTo/$a" in c for c in writes)
    assert all(c in _session("Emergency cleanup") for c in writes)


def test_the_agent_keeps_its_ownership_of_the_escalation_target() -> None:
    emergency = _session("Emergency cleanup")
    loop = re.search(r'foreach \(\$n in ("[^)]*")\) \{\n\s+if \(@\(az ad app owner list', emergency)
    assert loop is not None and loop[1] == '"id-verifier", "sp-fns-scout"'


def test_the_strike_cli_points_here_and_the_plans_link_it() -> None:
    cli = (ROOT / "src" / "fns" / "strike_cli.py").read_text(encoding="utf-8")
    assert "docs/runbooks/m4-live-run.md" in cli
    for doc in ("docs/milestones/M4-plan.md", "docs/milestones/M4-strikes-plan.md", "README.md"):
        assert "docs/runbooks/m4-live-run.md" in (ROOT / doc).read_text(encoding="utf-8"), doc
