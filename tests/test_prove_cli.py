"""``fns prove``, ``fns demo prove`` and ``fns verify`` end to end, on fixtures.

The verifier runs as a real subprocess here (``python -m fns.verify``).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.fixtures.replay import bundled
from fns.prove import run as prove_run
from tests.prove.helpers import LAB_RUN

ROOT = Path(__file__).resolve().parent
DEMO_SCOUT = str(bundled("demo-scout"))  # hand-written, for tests
runner = CliRunner()


def _golden(name: str) -> str:
    return (ROOT / "golden" / f"{name}.digest").read_text(encoding="utf-8").strip()


def _bundle_digest(output: str) -> str:
    m = re.search(r"bundle sha256:([0-9a-f]{64})", output)
    assert m, output
    return m.group(1)


def _run_dir(output: str) -> Path:
    m = re.search(r"run directory (\S+)", output)
    assert m, output
    return Path(m.group(1))


def _labelled(output: str) -> bool:
    return all(line.startswith("FIXTURE ") for line in output.splitlines() if line.strip())


@pytest.mark.parametrize(
    ("args", "golden"),
    [
        (["--fixture", DEMO_SCOUT], "demo-prove"),
        (["--fixture", str(LAB_RUN)], "lab-run-1-prove"),
        ([], "lab-run-2-prove"),
    ],
)
def test_demo_prove_is_labelled_deterministic_and_verifiable(
    tmp_path: Path, args: list[str], golden: str
) -> None:
    first = runner.invoke(app, ["demo", "prove", "--out", str(tmp_path / "a"), *args])
    second = runner.invoke(app, ["demo", "prove", "--out", str(tmp_path / "b"), *args])
    assert first.exit_code == second.exit_code == 1, first.output
    assert _labelled(first.output), first.output
    assert "TEST SIGNATURE" in first.output
    assert "separate process" in first.output
    assert _bundle_digest(first.output) == _bundle_digest(second.output) == _golden(golden)
    checked = runner.invoke(app, ["verify", str(_run_dir(first.output))])
    assert checked.exit_code == 0, checked.output
    assert "verified (offline-test)" in checked.output


def test_lab_run_verdicts(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["demo", "prove", "--out", str(tmp_path), "--fixture", str(LAB_RUN)]
    )
    out = result.output
    assert re.search(r"PASS\s+resource:stinvoicestiin02 blob/read\s+observed / verified", out)
    assert re.search(
        r"FAIL\s+resource:kv-crown-tiin02 secrets/get\s+evaluated / evaluated-only", out
    )
    assert "escalation paths remain" in out
    assert re.search(r"FAIL\s+directory:tenant roleAssignments/write\s+modeled / modeled-only", out)
    assert "passed: 1  critical reachable: 11  still-do failed: 0  inconclusive: 1" in out


def test_tampering_after_the_run_is_caught(tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", "prove", "--out", str(tmp_path)])
    run_dir = _run_dir(result.output)
    bundle = run_dir / "bundle.json"
    bundle.write_bytes(bundle.read_bytes().replace(b'"verdict":"fail"', b'"verdict":"pass"', 1))
    checked = runner.invoke(app, ["verify", str(run_dir)])
    assert checked.exit_code == 5, checked.output
    assert "EVIDENCE INVALID" in checked.output


def test_unsigned_run_does_not_verify(tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", "prove", "--out", str(tmp_path), "--sign", "none"])
    assert "UNSIGNED" in result.output
    checked = runner.invoke(app, ["verify", str(_run_dir(result.output))])
    assert checked.exit_code == 5


def test_prove_on_files(tmp_path: Path) -> None:
    from fns.contain_run import run_demo_contain

    scout, _ = run_demo_contain(tmp_path / "s", LAB_RUN)
    args = [
        "prove",
        "--contract",
        str(LAB_RUN / "contract.fns.yaml"),
        "--snapshot",
        str(scout.snapshot_path),
        "--probes",
        str(LAB_RUN / "probes.json"),
        "--out",
        str(tmp_path / "p"),
        "--identity",
        "fixture-replay",
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 1, result.output
    # Same inputs and the same verifier label as the demo: the same bundle.
    assert _bundle_digest(result.output) == _golden("lab-run-1-prove")
    bad = runner.invoke(app, [*args, "--sign", "gpg"])
    assert bad.exit_code == 2


def test_verifier_environment_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
        "AZURE_CLIENT_SECRET": "s",
        "azure_tenant_id": "t",
        "ARM_CLIENT_ID": "c",
        "MSI_ENDPOINT": "m",
        "IDENTITY_HEADER": "h",
        "GITHUB_TOKEN": "g",
        "ACTIONS_ID_TOKEN_REQUEST_URL": "keep",
        "PATH": "keep",
    }
    assert prove_run.verifier_env(env) == {"ACTIONS_ID_TOKEN_REQUEST_URL": "keep", "PATH": "keep"}
    seen: dict[str, object] = {}

    def fake_run(argv: list[str], **kw: object) -> object:
        seen.update(kw, argv=argv)
        raise SystemExit

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret")
    with pytest.raises(SystemExit):
        prove_run.spawn_verifier(["check", "--run", "x"])
    assert "AZURE_CLIENT_SECRET" not in seen["env"]  # type: ignore[operator]
    assert seen["argv"][1:3] == ["-m", "fns.verify"]  # type: ignore[index]
