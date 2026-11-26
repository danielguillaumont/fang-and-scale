"""ContainReport: references, determinism, schema, and the never-pass rule."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from pydantic import ValidationError

from fns import schema as schema_mod
from fns.contain.evaluate import evaluate
from fns.contain.report import build_report
from fns.contain_run import write_report
from fns.models.report import ContainReport
from tests.contain.helpers import RG, Snap, contract
from tests.factories import pid

AGENT = pid(100)
T1 = datetime(2026, 11, 26, 1, 0, tzinfo=UTC)
T2 = datetime(2026, 11, 27, 2, 0, tzinfo=UTC)
SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schemas" / "contain-report.schema.json"


def _report(when: datetime = T1, version: str = "1.0") -> ContainReport:
    s = Snap()
    s.sp(100, "sp-agent")
    s.kv()
    s.storage(allowSharedKeyAccess=False)
    s.rbac(AGENT, "Contributor", RG)
    c = contract(
        [
            {"resource": "kv-crown", "operations": ["secrets/get"]},
            {"directory": "tenant", "operations": ["roleAssignments/write"]},
        ],
        [{"resource": "stpayroll", "operations": ["blob/read"]}],
    )
    return build_report(evaluate(c, s.build()), generated_at=when, tool_version=version)


def test_evidence_points_at_the_shortest_path() -> None:
    r = _report()
    paths = {p.id: p for p in r.paths}
    fail = next(f for f in r.findings if f.verdict == "fail")
    (ev,) = fail.evidence
    assert ev.path_id is not None
    assert paths[ev.path_id].rank == 0
    assert paths[ev.path_id].finding_id == fail.id
    assert r.compromised_name == "sp-agent"


def test_digest_ignores_generation_time_and_tool_version() -> None:
    assert _report(T1, "1.0").digest() == _report(T2, "2.0").digest()


def test_mode_comes_from_the_snapshot() -> None:
    assert _report().mode == "FIXTURE"


def test_report_json_validates_against_committed_schema(tmp_path: Path) -> None:
    path = write_report(_report(), None, tmp_path)
    assert path.parent == tmp_path / "reports"
    raw = path.read_bytes()
    assert b"\r\n" not in raw
    data = json.loads(raw)
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    assert schema == schema_mod.schema_for("contain-report")
    jsonschema.Draft202012Validator(schema).validate(data)
    assert ContainReport.model_validate(data).digest() == _report().digest()


def test_rejects_dangling_references_and_tampered_paths() -> None:
    data = json.loads(_report().canonical_json())

    def variant() -> Any:
        return json.loads(json.dumps(data))

    broken = variant()
    broken["paths"][0]["finding_id"] = "0" * 64
    with pytest.raises(ValidationError):
        ContainReport.model_validate(broken)
    dangling = variant()
    dangling["paths"] = []
    with pytest.raises(ValidationError, match="unknown path"):
        ContainReport.model_validate(dangling)
    tampered = variant()
    tampered["paths"][0]["steps"][0]["text"] = "something else"
    with pytest.raises(ValidationError, match="path id"):
        ContainReport.model_validate(tampered)
