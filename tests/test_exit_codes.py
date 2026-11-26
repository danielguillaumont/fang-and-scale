"""One test per exit code in the README table, across every command that reads input.

0 within budget, 1 contract failed, 2 usage or invalid input, 3 inconclusive over
budget, 4 scope denied, 5 evidence invalid.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from fns import cli
from fns.cli import app
from fns.exitcodes import ExitCode
from fns.fixtures.replay import FixtureSet, bundled
from tests.factories import OTHER_TENANT
from tests.livekit import FakeCredential

ROOT = Path(__file__).resolve().parents[1]
LAB_RUN = ROOT / "fixtures" / "lab-run-1"
README = (ROOT / "README.md").read_text(encoding="utf-8")
runner = CliRunner()


@pytest.fixture(scope="module")
def snapshot(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("scout")
    result = runner.invoke(app, ["demo", "scout", "--fixture", str(LAB_RUN), "--out", str(out)])
    assert result.exit_code == 0, result.output
    (path,) = (out / "snapshots").glob("*.json")
    return path


def _contract(tmp_path: Path, **budget: object) -> Path:
    data = yaml.safe_load((LAB_RUN / "contract.fns.yaml").read_text(encoding="utf-8"))
    data.update(budget)
    path = tmp_path / "contract.fns.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def _contain(contract: Path, snapshot: Path, tmp_path: Path) -> int:
    result = runner.invoke(
        app,
        [
            "contain",
            "--contract",
            str(contract),
            "--snapshot",
            str(snapshot),
            "--out",
            str(tmp_path),
        ],
    )
    return result.exit_code


def test_readme_table_matches_the_enum() -> None:
    section = README.split("Exit codes:", 1)[1].split("\n\n", 1)[0]
    documented = {int(n) for n in re.findall(r"\b([0-9])\b", section)}
    assert documented == {int(c) for c in ExitCode}
    assert "2 usage or invalid input" in " ".join(section.split())


def test_0_within_budget(tmp_path: Path, snapshot: Path) -> None:
    loose = {"budget": {"max_critical_reachable": 99, "max_inconclusive": 99}}
    assert _contain(_contract(tmp_path, **loose), snapshot, tmp_path) == 0


def test_1_contract_failed(tmp_path: Path, snapshot: Path) -> None:
    assert _contain(LAB_RUN / "contract.fns.yaml", snapshot, tmp_path) == 1


def test_3_inconclusive_over_budget(tmp_path: Path, snapshot: Path) -> None:
    strict = {"budget": {"max_critical_reachable": 99, "max_inconclusive": 0}}
    assert _contain(_contract(tmp_path, **strict), snapshot, tmp_path) == 3


def test_4_scope_denied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import fns.adapters.azure.live as live
    import fns.scope.credentials as creds

    scope = FixtureSet.load(bundled("demo-scout")).scope_yaml
    scope = re.sub(r'expires_at: "?[0-9TZ:\-]+"?', 'expires_at: "2099-01-01T00:00:00Z"', scope)
    path = tmp_path / "scope.yaml"
    path.write_text(scope, encoding="utf-8")
    monkeypatch.setattr(
        creds, "_cli_credential", lambda tenant: FakeCredential({"arm": OTHER_TENANT})
    )
    monkeypatch.setattr(live, "default_opener", lambda: pytest.fail("no network"))
    result = runner.invoke(app, ["scout", "--scope", str(path), "--out", str(tmp_path / "o")])
    assert result.exit_code == 4, result.output


def test_5_evidence_invalid(tmp_path: Path) -> None:
    done = runner.invoke(app, ["demo", "prove", "--fixture", str(LAB_RUN), "--out", str(tmp_path)])
    m = re.search(r"run directory (\S+)", done.output)
    assert m, done.output
    run_dir = Path(m.group(1))
    bundle = run_dir / "bundle.json"
    bundle.write_bytes(bundle.read_bytes().replace(b'"verdict":"fail"', b'"verdict":"pass"', 1))
    assert runner.invoke(app, ["verify", str(run_dir)]).exit_code == 5


# -- 2: usage or invalid input, for every command that reads a file ---------------------


@pytest.fixture
def bad(tmp_path: Path) -> dict[str, Path]:
    files = {
        "contract": "version: 1\ncontract: x\n",  # missing required fields
        "scope": "version: 1\ntenant_id: not-a-guid\n",
        "garbage": "{not json",
        "dupkeys": "version: 1\nversion: 1\n",
    }
    out = {}
    for name, text in files.items():
        out[name] = tmp_path / f"{name}.txt"
        out[name].write_text(text, encoding="utf-8")
    out["missing"] = tmp_path / "does-not-exist"
    return out


INVALID = {
    "contain: invalid contract": ["contain", "--contract", "{contract}", "--snapshot", "{snap}"],
    "contain: invalid snapshot": ["contain", "--contract", "{lab}", "--snapshot", "{garbage}"],
    "contain: missing contract": ["contain", "--contract", "{missing}", "--snapshot", "{snap}"],
    "scope check: invalid scope": ["scope", "check", "{scope}"],
    "scope check: duplicate keys": ["scope", "check", "{dupkeys}"],
    "scope check: missing file": ["scope", "check", "{missing}"],
    "scout: invalid scope": ["scout", "--scope", "{scope}", "--out", "{tmp}"],
    "harden: invalid contract": ["harden", "--contract", "{contract}", "--snapshot", "{snap}"],
    "harden: missing lab": [
        *("harden", "--contract", "{lab}", "--snapshot", "{snap}"),
        "--lab",
        "{missing}",
    ],
    "mutate: missing lab": [
        *("mutate", "--contract", "{lab}", "--snapshot", "{snap}"),
        "--lab",
        "{missing}",
    ],
    "mutate: invalid contract": ["mutate", "--contract", "{contract}", "--snapshot", "{snap}"],
    "prove: invalid probes": [
        *("prove", "--contract", "{lab}", "--snapshot", "{snap}"),
        *("--probes", "{garbage}", "--out", "{tmp}"),
    ],
    "record: invalid log": ["record", "{garbage}", "--identity", OTHER_TENANT],
    "report: invalid report": ["report", "--contain", "{garbage}", "--out", "{tmp}/r.html"],
    "comment: invalid report": ["comment", "--contain", "{garbage}", "--out", "{tmp}/c.md"],
    "verify: not a run directory": ["verify", "{missing}"],
    "demo contain: missing fixture": [
        "demo",
        "contain",
        "--fixture",
        "{missing}",
        "--out",
        "{tmp}",
    ],
    "demo mutate: missing fixture": ["demo", "mutate", "--fixture", "{missing}", "--out", "{tmp}"],
    "usage: unknown option": ["contain", "--no-such-option"],
    "usage: unknown command": ["no-such-command"],
}


@pytest.mark.parametrize("args", list(INVALID.values()), ids=list(INVALID))
def test_2_invalid_input(
    args: list[str], bad: dict[str, Path], snapshot: Path, tmp_path: Path
) -> None:
    values = {k: str(v) for k, v in bad.items()}
    values |= {"snap": str(snapshot), "lab": str(LAB_RUN / "contract.fns.yaml")}
    values["tmp"] = str(tmp_path)
    argv = [a.format(**values) for a in args]
    result = runner.invoke(app, argv)
    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception


def test_2_internal_error_is_never_a_verdict(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def crash() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "app", crash)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert "internal error" in capsys.readouterr().err


def test_action_passes_error_codes_through() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    script = action.split("verdict() {", 1)[1].split("\n        }", 1)[0]
    assert "0|1|3)" in script
    assert 'exit "$code"' in script
