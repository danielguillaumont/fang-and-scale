"""``fns strike`` from the recorded fixture: plan, approve, run, cleanup (FIXTURE)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from fns.adapters.azure.http import ApiRequest
from fns.cli import app
from fns.scope.targets import DirectoryTarget
from fns.strike.replay import ReplayError, ReplayReads, ReplayWrites, load_recording
from fns.strike.secrets import SecretHolder
from fns.strike.transport import StrikeRequest
from tests.strike.make_fixture import FIXTURE_DIR, files

runner = CliRunner()
FIX = FIXTURE_DIR.as_posix()
HASH = re.compile(r"plan sha256:([0-9a-f]{64})")


def test_committed_fixture_matches_the_generator() -> None:
    for name, text in files().items():
        assert (FIXTURE_DIR / name).read_bytes().decode() == text, (
            f"{name} drifted: uv run python -m tests.strike.make_fixture"
        )


def test_fixture_holds_no_secret_and_only_placeholders() -> None:
    for path in FIXTURE_DIR.iterdir():
        text = path.read_text()
        assert "FAKE-SECRET" not in text and "FAKE-TOKEN" not in text
        for guid in re.findall(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text
        ):
            assert guid.startswith("00000000-0000-4000-8000-"), (path.name, guid)


def _out(result: Any) -> list[str]:
    return [line for line in result.output.splitlines() if line.strip()]


def plan(tmp: Path, strikes: str = "S1,S2,S3") -> tuple[Path, str]:
    r = runner.invoke(
        app, ["strike", "plan", "--strikes", strikes, "--fixture", FIX, "--out", str(tmp)]
    )
    assert r.exit_code == 0, r.output
    m = HASH.search(r.output)
    assert m is not None
    plans = sorted(tmp.glob("*/plan.json"))
    assert len(plans) == 1
    assert all(line.startswith("FIXTURE") for line in _out(r))
    return plans[0], m[1]


def run(plan_path: Path, h: str, *extra: str) -> Any:
    return runner.invoke(
        app,
        [
            "strike",
            "run",
            "--plan",
            str(plan_path),
            "--approve",
            f"sha256:{h}",
            "--fixture",
            FIX,
            *extra,
        ],
    )


def test_plan_is_deterministic(tmp_path: Path) -> None:
    _, a = plan(tmp_path / "a")
    _, b = plan(tmp_path / "b")
    assert a == b


def test_before_harden_replay(tmp_path: Path) -> None:
    p, h = plan(tmp_path)
    r = run(p, h)
    assert r.exit_code == 0, r.output
    assert all(line.startswith("FIXTURE") for line in _out(r))
    assert "exit 0: clean" in r.output
    data = json.loads((p.parent / "strike-run.json").read_text())
    assert data["mode"] == "FIXTURE" and data["exit_code"] == 0
    assert [w["outcome"] for w in data["writes"]] == ["succeeded"] * 3
    assert all(c["ok"] for c in data["verification"])


def test_after_harden_replay(tmp_path: Path) -> None:
    p, h = plan(tmp_path, "D-1,D-2,D-3,D-4,D-5")
    r = run(p, h)
    assert r.exit_code == 0, r.output
    data = json.loads((p.parent / "strike-run.json").read_text())
    assert [w["outcome"] for w in data["writes"]] == ["denied"] * 5
    assert data["writes"][1]["observes"] == [
        "application:id-verifier credentials/update",
        "directory:tenant applications/credentials/update",
    ]


def test_wrong_hash_is_refused_with_4(tmp_path: Path) -> None:
    p, _ = plan(tmp_path)
    r = run(p, "0" * 64)
    assert r.exit_code == 4 and "refused" in r.output
    assert not (p.parent / "strike-run.json").exists()


def test_a_tampered_plan_file_is_refused(tmp_path: Path) -> None:
    p, h = plan(tmp_path)
    data = json.loads(p.read_text())
    data["writes"][1]["request"]["body"]["tags"]["fns-strike"] = "other"
    p.write_text(json.dumps(data))
    r = run(p, h)
    assert r.exit_code == 4 and "does not match" in r.output


def test_cleanup_after_a_clean_run_has_nothing_to_do(tmp_path: Path) -> None:
    p, h = plan(tmp_path)
    journal = tmp_path / "j.sqlite"
    assert run(p, h, "--journal", str(journal)).exit_code == 0
    r = runner.invoke(
        app,
        [
            "strike",
            "cleanup",
            "--plan",
            str(p),
            "--approve",
            h,
            "--journal",
            str(journal),
            "--fixture",
            FIX,
        ],
    )
    assert r.exit_code == 0, r.output
    assert json.loads((p.parent / "cleanup.json").read_text())["writes"] == []


def test_the_same_journal_refuses_a_second_run(tmp_path: Path) -> None:
    p, h = plan(tmp_path)
    journal = tmp_path / "j.sqlite"
    assert run(p, h, "--journal", str(journal)).exit_code == 0
    r = run(p, h, "--journal", str(journal))
    assert r.exit_code == 4 and "already ran" in r.output


def test_wrong_strikes_for_the_recording(tmp_path: Path) -> None:
    r = runner.invoke(
        app, ["strike", "plan", "--strikes", "S1", "--fixture", FIX, "--out", str(tmp_path)]
    )
    assert r.exit_code == 2 and "S1, S2, S3" in r.output


@pytest.mark.parametrize(
    "args",
    [
        ["strike", "plan", "--strikes", "S1,S2,S3"],  # live without --scout-config
        ["strike", "plan", "--strikes", ""],
    ],
)
def test_usage_errors(tmp_path: Path, args: list[str]) -> None:
    r = runner.invoke(
        app, [*args, "--out", str(tmp_path), "--scope", str(FIXTURE_DIR / "scope.yaml")]
    )
    assert r.exit_code == 2, r.output


def test_live_run_needs_the_agent_config(tmp_path: Path) -> None:
    p, h = plan(tmp_path)
    scope = str(FIXTURE_DIR / "scope.yaml")
    args = ["strike", "run", "--plan", str(p), "--approve", h, "--scope", scope]
    r = runner.invoke(app, [*args, "--scout-config", str(tmp_path)])
    assert r.exit_code == 2 and "agent-config" in r.output


def test_live_with_a_missing_config_dir_sends_nothing(tmp_path: Path) -> None:
    """The fixture scope has expired for the wall clock, so use a scope check first."""
    scope = str(FIXTURE_DIR / "scope.yaml")
    args = ["strike", "plan", "--strikes", "S1", "--scope", scope, "--out", str(tmp_path)]
    r = runner.invoke(app, [*args, "--scout-config", str(tmp_path / "nope")])
    assert r.exit_code == 2


# --- replay transports ----------------------------------------------------------------


def test_replay_writes_refuse_a_different_request() -> None:
    rec = load_recording(FIXTURE_DIR, "before-harden")
    w = ReplayWrites(rec)
    first = rec.writes[0]
    with pytest.raises(ReplayError, match="differs"):
        w.send(StrikeRequest("arm", "POST", first.url, {"x": 1}), SecretHolder(), "k")
    w2 = ReplayWrites(rec)
    for recorded in rec.writes:
        assert recorded.status in (200, 204)
    w2._writes.clear()
    with pytest.raises(ReplayError, match="no more"):
        w2.send(StrikeRequest("arm", "POST", first.url), SecretHolder(), "k")


def test_replay_reads_by_phase() -> None:
    rec = load_recording(FIXTURE_DIR, "before-harden")
    assert rec.plan_reads and rec.reads
    reads = ReplayReads(rec, "plan")
    with pytest.raises(ReplayError, match="no recorded read"):
        reads.fetch(
            ApiRequest(
                "graph",
                "graph:GET /applications",
                DirectoryTarget(),
                "https://graph.microsoft.com/v1.0/x",
            )
        )
