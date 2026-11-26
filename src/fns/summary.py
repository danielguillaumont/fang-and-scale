"""Shared output for ``fns scout`` and ``fns demo scout``."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from rich.table import Table

from fns.models.ids import utc_isoformat
from fns.models.snapshot import Snapshot

STATUS_STYLE = {
    "complete": "fns.pass",
    "partial": "fns.inconclusive",
    "skipped": "fns.inconclusive",
    "failed": "fns.fail",
}


class Printer(Protocol):
    def print(self, *objects: Any, **kwargs: Any) -> None: ...


@dataclass(frozen=True)
class ScoutResult:
    snapshot: Snapshot
    digest: str
    snapshot_path: Path
    journal_path: Path
    run_id: str
    calls: int
    fixture_path: Path | None = None


def write_snapshot(snapshot: Snapshot, snapshots_dir: Path) -> tuple[str, Path]:
    digest = snapshot.digest()
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    path = snapshots_dir / f"{digest}.{snapshot.mode}.json"
    text = json.dumps(
        json.loads(snapshot.canonical_json()), indent=2, sort_keys=True, ensure_ascii=False
    )
    path.write_text(text + "\n", encoding="utf-8", newline="\n")
    return digest, path


def render_summary(result: ScoutResult, out: Printer) -> None:
    snap = result.snapshot
    out.print(
        f"tenant {snap.tenant_id}  collected_at {utc_isoformat(snap.collected_at)}", markup=False
    )

    table = Table(title="Collectors", title_justify="left", show_edge=False, pad_edge=False)
    table.add_column("collector")
    table.add_column("status")
    table.add_column("items", justify="right")
    table.add_column("errors")
    for c in snap.coverage.collectors:
        table.add_row(
            c.name,
            f"[{STATUS_STYLE[c.status]}]{c.status}[/]",
            str(c.items),
            ", ".join(c.error_codes) or "-",
        )
    out.print(table)

    def counts(title: str, counter: Counter[str]) -> None:
        parts = "  ".join(f"{k}={v}" for k, v in sorted(counter.items()))
        out.print(f"{title}: {sum(counter.values())}  ({parts})", markup=False)

    counts("entities", Counter(e.type for e in snap.entities))
    counts("edges", Counter(e.type for e in snap.edges))
    out.print(
        "not collected (findings that depend on these will be inconclusive):",
        style="fns.inconclusive",
    )
    for nc in snap.coverage.not_collected:
        out.print(f"  - {nc.surface}: {nc.reason}", markup=False)
    out.print(f"gated API calls: {result.calls}  run {result.run_id}", markup=False)
    out.print(f"snapshot {result.snapshot_path.as_posix()}", markup=False)
    if result.fixture_path is not None:
        out.print(f"recorded fixture {result.fixture_path.as_posix()}", markup=False)
    out.print(f"digest sha256:{result.digest}", style="fns.highlight")
