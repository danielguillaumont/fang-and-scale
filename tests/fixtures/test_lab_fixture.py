"""The first recorded lab run (M1 Phase B, 2026-11-26) as a regression fixture.

It pins three things the live run established: the real API shapes still parse
into a complete snapshot, the replay digest is stable, and the well-known IDs
the sanitizer keeps verbatim match what the tenant returned.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fns.demo import run_demo_scout
from fns.fixtures import wellknown
from fns.fixtures.recorder import SCOPE_HEADER, _strip_leading_comments

ROOT = Path(__file__).resolve().parents[2]
LAB_RUN = ROOT / "fixtures" / "lab-run-1"
GOLDEN = (ROOT / "tests" / "golden" / "lab-run-1.digest").read_text(encoding="utf-8").strip()


def _items() -> list[dict[str, Any]]:
    exchanges = json.loads((LAB_RUN / "exchanges.json").read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = []
    for exchange in exchanges:
        body = exchange["response"]["body"]
        if isinstance(body, dict):
            out.append(body)
            out.extend(i for i in body.get("value", []) if isinstance(i, dict))
    return out


def _constant(name: str) -> str | None:
    """``Application.ReadWrite.All`` -> ``wellknown.APPLICATION_READWRITE_ALL``."""
    value = getattr(wellknown, re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_"), None)
    return value if isinstance(value, str) else None


def test_replay_is_complete_and_matches_golden(tmp_path: Path) -> None:
    first = run_demo_scout(tmp_path / "a", LAB_RUN)
    second = run_demo_scout(tmp_path / "b", LAB_RUN)
    assert first.digest == second.digest == GOLDEN
    snap = first.snapshot
    assert snap.mode == "FIXTURE"
    assert {c.status for c in snap.coverage.collectors} == {"complete"}
    assert (len(snap.entities), len(snap.edges), first.calls) == (210, 31, 28)


def test_graph_app_role_ids_match_wellknown() -> None:
    graph = [i for i in _items() if i.get("appId") == wellknown.MICROSOFT_GRAPH_APP_ID]
    assert len(graph) == 1
    checked = 0
    for role in graph[0]["appRoles"]:
        expected = _constant(role["value"])
        if expected is not None:
            assert role["id"] == expected, role["value"]
            checked += 1
    assert checked >= 7


def test_rbac_and_directory_role_ids_match_wellknown() -> None:
    checked = 0
    for item in _items():
        props = item.get("properties") or {}
        if props.get("type") == "BuiltInRole":
            assert item["name"] == _constant(props["roleName"]), props["roleName"]
            checked += 1
        if item.get("isBuiltIn") and _constant(item["displayName"]) is not None:
            assert item["templateId"] == _constant(item["displayName"]), item["displayName"]
            checked += 1
    assert checked >= 10


def test_recorded_scope_header_is_rewritten() -> None:
    text = (LAB_RUN / "scope.yaml").read_text(encoding="utf-8")
    assert text.startswith(SCOPE_HEADER)
    assert "Do not edit or commit" not in text
    assert _strip_leading_comments("# a\n# b\nversion: 1\n# keep\n") == "version: 1\n# keep\n"
