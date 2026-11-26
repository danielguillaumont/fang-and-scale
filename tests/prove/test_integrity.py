"""The verifier refuses tampered or out-of-order runs, and never writes the journal."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from fns.journal.sqlite import SqliteJournal
from fns.verify import inputs as vin
from fns.verify.inputs import IntegrityError, load_inputs, open_read_only
from tests.prove.helpers import prepared


def test_untampered_run_loads(tmp_path: Path) -> None:
    aset, run_dir, probes, _ = prepared(tmp_path)
    got = load_inputs(run_dir)
    assert got.assertions == aset
    assert set(got.observations) == {o.probe_id for o in probes.observations}
    assert got.unfinished == ()


def test_edited_assertions_are_rejected(tmp_path: Path) -> None:
    _, run_dir, _, _ = prepared(tmp_path)
    path = run_dir / "assertions.json"
    data = json.loads(path.read_bytes())
    data["thresholds"]["max_critical_reachable"] = 99
    path.write_bytes((json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode())
    with pytest.raises(IntegrityError, match="differs from the digest frozen"):
        load_inputs(run_dir)


def test_non_canonical_assertions_are_rejected(tmp_path: Path) -> None:
    _, run_dir, _, _ = prepared(tmp_path)
    path = run_dir / "assertions.json"
    path.write_bytes(json.dumps(json.loads(path.read_bytes()), indent=2).encode())
    with pytest.raises(IntegrityError, match="canonical"):
        load_inputs(run_dir)


def test_tampered_artifact_is_rejected(tmp_path: Path) -> None:
    _, run_dir, _, _ = prepared(tmp_path)
    artifact = sorted((run_dir / "artifacts").iterdir())[0]
    artifact.write_bytes(artifact.read_bytes().replace(b'"denied"', b'"allowed"'))
    with pytest.raises(IntegrityError, match="does not match its digest"):
        load_inputs(run_dir)


def test_missing_artifact_is_rejected(tmp_path: Path) -> None:
    _, run_dir, _, _ = prepared(tmp_path)
    sorted((run_dir / "artifacts").iterdir())[0].unlink()
    with pytest.raises(IntegrityError, match="cannot read"):
        load_inputs(run_dir)


def _append(run_dir: Path, run_id: str, key: str, value: str = "x") -> None:
    with SqliteJournal(run_dir / "journal.sqlite") as j:
        j.run_step(run_id, key, "read", "injected", lambda: value, digest=lambda v: v)


def test_unknown_probe_step_is_rejected(tmp_path: Path) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    _append(run_dir, aset.run_id, "probe:" + "f" * 64)
    with pytest.raises(IntegrityError, match="not frozen"):
        load_inputs(run_dir)


def test_unexpected_step_is_rejected(tmp_path: Path) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    _append(run_dir, aset.run_id, "something-else")
    with pytest.raises(IntegrityError, match="unexpected journal step"):
        load_inputs(run_dir)


def test_probe_before_freeze_is_rejected(tmp_path: Path) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    # Rebuild the journal with a probe event first, then the freeze.
    data = (run_dir / "assertions.json").read_bytes()
    (run_dir / "journal.sqlite").unlink()
    first = aset.assertions[0].probes[0] if aset.assertions[0].probes else None
    spec = first or next(p for a in aset.assertions for p in a.probes)
    with SqliteJournal(run_dir / "journal.sqlite") as j:
        j.begin_run(aset.run_id, "prove", aset.mode)
        j.run_step(
            aset.run_id, f"probe:{spec.id}", "read", "early", lambda: "x", digest=lambda v: v
        )
        import hashlib

        digest = hashlib.sha256(data).hexdigest()
        j.run_step(
            aset.run_id, "freeze-assertions", "read", "late", lambda: digest, digest=lambda v: v
        )
    with pytest.raises(IntegrityError, match="before the assertions were frozen"):
        load_inputs(run_dir)


def test_never_frozen_is_rejected(tmp_path: Path) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    (run_dir / "journal.sqlite").unlink()
    with SqliteJournal(run_dir / "journal.sqlite") as j:
        j.begin_run(aset.run_id, "prove", aset.mode)
    with pytest.raises(IntegrityError, match="never frozen"):
        load_inputs(run_dir)


def test_journal_mode_mismatch_is_rejected(tmp_path: Path) -> None:
    aset, run_dir, _, _ = prepared(tmp_path)
    (run_dir / "journal.sqlite").unlink()
    with SqliteJournal(run_dir / "journal.sqlite") as j:
        j.begin_run(aset.run_id, "prove", "LIVE")
    with pytest.raises(IntegrityError, match="mode"):
        load_inputs(run_dir)


def test_the_verifier_opens_the_journal_read_only(tmp_path: Path) -> None:
    _, run_dir, _, _ = prepared(tmp_path)
    before = (run_dir / "journal.sqlite").read_bytes()
    load_inputs(run_dir)
    assert (run_dir / "journal.sqlite").read_bytes() == before
    conn = open_read_only(run_dir / "journal.sqlite")
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("CREATE TABLE x (y INTEGER)")
    finally:
        conn.close()


def test_verifier_source_connects_only_read_only() -> None:
    src = Path(vin.__file__).read_text(encoding="utf-8")
    assert src.count("sqlite3.connect(") == 1
    assert '"?mode=ro"' in src
    package = Path(vin.__file__).parent
    for path in package.glob("*.py"):
        if path.name != "inputs.py":
            assert "sqlite3" not in path.read_text(encoding="utf-8"), path.name
