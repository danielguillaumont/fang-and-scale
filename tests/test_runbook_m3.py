"""The M3 runbook's safety rules for the escalation-capable test identity.

``docs/runbooks/m3-live-run.md`` is run by hand against a real tenant. These
checks keep its text to the rules the owner set: a certificate (never a secret)
valid for at most a day, created just before the probes and deleted just after,
verified empty, nothing else run as the agent, and an emergency cleanup.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "runbooks" / "m3-live-run.md"
TEXT = RUNBOOK.read_text(encoding="utf-8")
BLOCKS = re.findall(r"```powershell\n(.*?)```", TEXT, re.S)
COMMANDS = [
    line.split("#", 1)[0].strip()
    for block in BLOCKS
    for line in block.splitlines()
    if line.split("#", 1)[0].strip()
]


def _section(heading: str) -> str:
    start = TEXT.index(heading)
    nxt = TEXT.find("\n## ", start + len(heading))
    return TEXT[start : nxt if nxt != -1 else len(TEXT)]


def test_the_agent_warning_box_is_there() -> None:
    box = _section("## 5. Create the `sp-billing-agent` certificate")
    assert "> [!CAUTION]" in box
    assert "escalation-capable identity" in box
    assert "at most 1 day" in box
    assert "Emergency cleanup" in box


def test_credentials_are_short_lived_certificates_only() -> None:
    resets = [c for c in COMMANDS if "az ad app credential reset" in c]
    assert len(resets) == 2  # the scout, then the agent
    for cmd in resets:
        assert "--create-cert" in cmd and "--append" in cmd, cmd
        assert "--end-date $end" in cmd
        assert "--years" not in cmd and "--password" not in cmd
    ends = [c for c in COMMANDS if c.startswith("$end = ")]
    assert ends and all("AddHours(23)" in c for c in ends)
    for banned in (
        "create-for-rbac",
        "sp credential reset",
        "credential reset --id $agentId --cert",
    ):
        assert banned not in TEXT


def test_the_agent_credential_is_checked_before_and_after() -> None:
    step5 = _section("## 5. Create the `sp-billing-agent` certificate")
    before = step5.index("az ad app credential list --id $agentId --cert -o tsv")
    assert before < step5.index("az ad app credential reset")
    assert "AddHours(24)" in step5 and "$certs.Count -ne 1" in step5
    step7 = _section("## 7. Sign the agent out and delete its certificate")
    delete = step7.index("az ad app credential delete --id $agentId")
    for check in (
        "az ad app credential list --id $agentId --cert -o tsv",
        "az ad app credential list --id $agentId -o tsv",
        "az ad sp credential list --id $agentId --cert -o tsv",
        "Test-Path $agentCred.fileWithCertAndPrivateKey",
    ):
        assert step7.index(check) > delete, check


def test_nothing_else_runs_as_the_agent() -> None:
    start = COMMANDS.index("$env:AZURE_CONFIG_DIR = $agentDir")
    end = COMMANDS.index("Remove-Item Env:AZURE_CONFIG_DIR", start)
    as_agent = COMMANDS[start + 1 : end]
    allowed = (
        "az login --service-principal",
        "az account show",
        "uv run fns prove",
        "$LASTEXITCODE",
    )
    assert as_agent[-1] == "az logout"
    for cmd in as_agent[:-1]:
        assert cmd.startswith(allowed), cmd
    assert sum(c.startswith("uv run fns prove") for c in as_agent) == 1


def test_the_agent_certificate_is_deleted_right_after_the_probes() -> None:
    prove = next(i for i, c in enumerate(COMMANDS) if c.startswith("uv run fns prove"))
    delete = next(i for i, c in enumerate(COMMANDS) if "credential delete --id $agentId" in c)
    between = COMMANDS[prove + 1 : delete]
    assert not [c for c in between if c.startswith(("uv run", "terraform", "git"))], between


def test_emergency_cleanup_covers_both_identities_and_the_pem_files() -> None:
    em = _section("## Emergency cleanup (if the session dies midway)")
    for needle in (
        "az ad app list --display-name sp-billing-agent",
        "az ad app list --display-name sp-fns-scout",
        "az ad app credential delete",
        "tmp*.pem",
        "PRIVATE KEY",
        "fns-agent-az",
        "az account clear",
        "fixtures\\lab-run-3",
    ):
        assert needle in em, needle
    assert "Verify." in em


def test_the_scope_is_renewed() -> None:
    # Unquoted, PowerShell mangled -replace=a.b in the M3 live run (2026-11-26).
    assert 'terraform -chdir=lab apply "-replace=time_offset.scope_expiry"' in COMMANDS
    assert "terraform -chdir=lab apply -replace=" not in TEXT
    assert "2026-12-03" in TEXT
    assert "**2 to add, 1 to change, 2\nto destroy**" in TEXT


@pytest.mark.parametrize(
    "path",
    [
        "docs/runbooks/m1-live-run.md",
        "docs/runbooks/m2-live-run.md",
        "docs/runbooks/m3-live-run.md",
        "docs/milestones/M3-live-plan.md",
        "lab/scope.tf",
    ],
)
def test_the_replace_argument_is_quoted_everywhere(path: str) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    assert '"-replace=time_offset.scope_expiry"' in text
    assert " -replace=time_offset" not in text


@pytest.mark.parametrize("var", ["$scoutDir", "$agentDir", "$p"])
def test_temp_profiles_are_removed_with_a_retry(var: str) -> None:
    """In M3 one Remove-Item failed on a file Windows still held, and worked 10 s later."""
    assert f"Remove-Item -Recurse -Force {var} -ErrorAction SilentlyContinue" in COMMANDS
    i = COMMANDS.index(f"Remove-Item -Recurse -Force {var} -ErrorAction SilentlyContinue")
    assert COMMANDS[i - 1] == "foreach ($i in 1..5) {"
    assert COMMANDS[i + 1] == f"if (-not (Test-Path {var})) {{ break }}"
    assert COMMANDS[i + 2] == "Start-Sleep -Seconds 3"
    assert not [
        c for c in COMMANDS if c.startswith("Remove-Item -Recurse -Force") and c.endswith("Dir")
    ]


def test_the_secret_value_is_never_read_by_hand() -> None:
    assert not [c for c in COMMANDS if "az keyvault secret show" in c]
    assert not [c for c in COMMANDS if "listKeys" in c or "storage account keys" in c]


@pytest.mark.parametrize("command", ["prove", "scout", "demo prove"])
def test_the_fns_options_the_runbook_uses_exist(command: str) -> None:
    used = {
        flag
        for c in COMMANDS
        if c.startswith(f"uv run fns {command} ")
        for flag in re.findall(r"(--[a-z-]+)", c)
    }
    assert used, command
    sub = command.split()
    help_text = CliRunner().invoke(app, [*sub, "--help"], terminal_width=200).output
    for flag in used:
        assert flag in help_text, (command, flag)
