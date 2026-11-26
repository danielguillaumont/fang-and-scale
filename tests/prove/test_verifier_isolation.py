"""V1: the verifier holds no Azure credential and cannot pick up the CLI login.

The scrubbed environment removes credential variables; ``AZURE_CONFIG_DIR``
points the Azure CLI at an empty directory made for the one verifier process, so
``~/.azure`` (``azureProfile.json``, the MSAL token cache) is out of reach.
Nothing here runs ``az`` or calls Azure: the child process resolves the CLI's
config directory the way the CLI does and tries to read the login files.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from fns.prove import run as prove_run

CANARY = "fns-cli-login-canary-7f3a"
REAL_RUN = subprocess.run  # tests below replace subprocess.run; the child must not
LOGIN_FILES = (
    "azureProfile.json",
    "msal_token_cache.json",
    "msal_token_cache.bin",
    "accessTokens.json",
    "service_principal_entries.json",
    "service_principal_entries.bin",
)

# Resolves the Azure CLI config dir as azure-cli-core does (AZURE_CONFIG_DIR, else
# ~/.azure) and reports every login file it can read and whether the canary shows.
CHILD = r"""
import json, os, sys
from pathlib import Path
cfg = Path(os.environ.get("AZURE_CONFIG_DIR") or Path.home() / ".azure")
names = json.loads(sys.argv[1])
found = [n for n in names if (cfg / n).exists()]
canary = sys.argv[2]
leaked = any(canary in v for v in os.environ.values())
leaked = leaked or any(canary in (cfg / n).read_text(errors="ignore") for n in found)
listing = sorted(p.name for p in cfg.iterdir()) if cfg.is_dir() else None
print(json.dumps({"cfg": str(cfg), "found": found, "leaked": leaked, "listing": listing}))
"""


def _fake_login(home: Path) -> Path:
    """A signed-in Azure CLI: every login file, each holding the canary."""
    azure = home / ".azure"
    azure.mkdir(parents=True)
    for name in LOGIN_FILES:
        azure.joinpath(name).write_text(json.dumps({"token": CANARY}), encoding="utf-8")
    return azure


def _child(env: dict[str, str]) -> dict[str, Any]:
    done = REAL_RUN(  # this interpreter, a fixed script
        [sys.executable, "-I", "-c", CHILD, json.dumps(LOGIN_FILES), CANARY],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    result: dict[str, Any] = json.loads(done.stdout)
    return result


@pytest.fixture
def signed_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    azure = _fake_login(home)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("AZURE_CONFIG_DIR", str(azure))
    monkeypatch.setenv("AZURE_ACCESS_TOKEN", CANARY)
    return azure


def test_the_fake_login_is_readable_without_isolation(signed_in: Path) -> None:
    """The control: a plain child process does find the login."""
    seen = _child(dict(os.environ))
    assert seen["found"] == list(LOGIN_FILES)
    assert seen["leaked"] is True


def test_the_verifier_environment_cannot_read_the_cli_login(
    signed_in: Path, tmp_path: Path
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    env = prove_run.verifier_env(azure_config_dir=str(empty))
    assert env["AZURE_CONFIG_DIR"] == str(empty)
    assert "AZURE_ACCESS_TOKEN" not in env
    seen = _child(env)
    assert Path(seen["cfg"]) == empty
    assert seen["found"] == []
    assert seen["listing"] == []
    assert seen["leaked"] is False


def test_without_a_config_dir_the_scrub_alone_falls_back_to_home(signed_in: Path) -> None:
    """Why V1 needs AZURE_CONFIG_DIR: scrubbing AZURE_* sends the CLI back to ~/.azure."""
    seen = _child(prove_run.verifier_env())
    assert seen["found"] == list(LOGIN_FILES)


def test_spawn_verifier_gives_each_run_a_new_empty_config_dir(
    signed_in: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        cfg = Path(kw["env"]["AZURE_CONFIG_DIR"])
        seen.append({"cfg": cfg, "listing": sorted(cfg.iterdir()), "child": _child(kw["env"])})
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("subprocess.run", fake_run)
    prove_run.spawn_verifier(["check", "--run", "x"])
    prove_run.spawn_verifier(["check", "--run", "x"])
    first, second = seen
    assert first["cfg"] != second["cfg"]
    for s in seen:
        assert s["cfg"] != signed_in
        assert s["listing"] == []
        assert s["child"]["found"] == []
        assert s["child"]["leaked"] is False
        assert not s["cfg"].exists()  # removed once the verifier exits


def test_the_real_verifier_runs_with_the_empty_config_dir(signed_in: Path) -> None:
    """End to end through the real verifier entry point: it starts and exits cleanly."""
    done = prove_run.spawn_verifier(["--help"])
    assert done.returncode == 0, done.stderr
    assert CANARY not in done.stdout + done.stderr
