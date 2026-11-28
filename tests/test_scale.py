"""The scale test's generator and stages, at a size CI can afford.

``uv run poe scale`` runs the same code at 10,000 service principals
(docs/PERFORMANCE.md). Here: a small synthetic tenant is deterministic, the
replayed snapshot has the shape the big run reports, both contracts evaluate,
and every artefact is FIXTURE with placeholder GUIDs only.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from fns.contain_run import contain
from fns.demo import run_demo_scout
from fns.models.contract import load_contract

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("scale_test", ROOT / "scripts" / "scale_test.py")
assert _spec is not None and _spec.loader is not None
scale: Any = importlib.util.module_from_spec(_spec)
sys.modules["scale_test"] = scale  # dataclasses resolve their module
_spec.loader.exec_module(scale)

SPS = 60
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("scale") / "fixture"
    scale.write_fixture(out, scale.Size(SPS))
    return out


def test_the_tenant_is_deterministic() -> None:
    a, _ = scale.tenant(scale.Size(SPS))
    b, _ = scale.tenant(scale.Size(SPS))
    assert a == b
    c, _ = scale.tenant(scale.Size(SPS), seed=1)
    assert a != c


def test_ids_do_not_collide_at_the_big_size() -> None:
    t, _ = scale.tenant(scale.Size(10_000))
    ids = [x for p in t.principals for x in (p.sp, p.app, p.app_id)]
    ids += [scale.bs.pid(g.n) for g in t.groups]
    assert len(ids) == len(set(ids))
    assignments = {scale.bs.pid(700 + i) for i in range(len(t.grants))}
    assert not assignments & set(ids)


def test_the_fixture_is_labelled_and_uses_placeholder_guids(fixture_dir: Path) -> None:
    manifest = json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["label"] == "FIXTURE"
    text = (fixture_dir / "exchanges.json").read_text(encoding="utf-8")
    allowed = {g.lower() for g in GUID.findall(text) if g.startswith("00000000-0000-4000-8000-")}
    public = {g.lower() for g in GUID.findall(text)} - allowed
    # Only Microsoft's public IDs (built-in roles, Graph app and app roles) are not placeholders.
    known = {v.lower() for v in vars(scale.wk).values() if isinstance(v, str) and GUID.fullmatch(v)}
    assert public <= known, sorted(public - known)


def test_replay_is_deterministic_and_has_the_reported_shape(
    fixture_dir: Path, tmp_path: Path
) -> None:
    one = run_demo_scout(tmp_path / "a", fixture_dir)
    two = run_demo_scout(tmp_path / "b", fixture_dir)
    assert one.digest == two.digest
    snap = one.snapshot
    assert snap.mode == "FIXTURE"
    assert len(snap.edges) >= 4 * SPS  # about five per service principal at every size
    assert one.calls >= 3 * SPS


def test_both_contracts_evaluate_deterministically(fixture_dir: Path, tmp_path: Path) -> None:
    snap = run_demo_scout(tmp_path, fixture_dir).snapshot
    for name in ("contract.fns.yaml", "wide.fns.yaml"):
        c = load_contract(fixture_dir / name)
        first = contain(c, snap, now=snap.collected_at)
        again = contain(c, snap, now=snap.collected_at)
        assert first.digest() == again.digest()
        assert first.mode == "FIXTURE"
    wide = contain(load_contract(fixture_dir / "wide.fns.yaml"), snap, now=snap.collected_at)
    assert wide.summary.critical > 0, "the wide agent (Owner on the resource group) reaches"


def test_the_opt_in_task_runs_the_big_size() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'scale.cmd = "python scripts/scale_test.py --sps 10000"' in text
    check = text.split("check.sequence = ", 1)[1].split("\n", 1)[0]
    assert "scale" not in check, "the big run stays opt-in"
