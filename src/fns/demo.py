"""``fns demo scout``: replay the bundled fixture through the real pipeline.

The demo uses the same scope gate, collector and journal as a live run. Only
the transport (fixture replay) and the clock (frozen at the fixture's
``recorded_at``) differ, so the output is deterministic and the short demo
scope expiry stays valid. Every line of output is labelled FIXTURE.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from rich.table import Table

from fns.console import FixtureConsole
from fns.fixtures.replay import FixtureSet, FixtureTransport, bundled
from fns.inventory.collector import Collector
from fns.journal.sqlite import SqliteJournal
from fns.models.ids import utc_isoformat
from fns.models.scope import parse_scope
from fns.models.snapshot import Snapshot
from fns.scope.gate import FrozenClock, Gate

DEMO_FIXTURE = "demo-scout"

STATUS_STYLE = {
    "complete": "fns.pass",
    "partial": "fns.inconclusive",
    "skipped": "fns.inconclusive",
    "failed": "fns.fail",
}


@dataclass(frozen=True)
class DemoResult:
    snapshot: Snapshot
    digest: str
    snapshot_path: Path
    journal_path: Path
    run_id: str
    calls: int


def write_snapshot(snapshot: Snapshot, snapshots_dir: Path) -> tuple[str, Path]:
    digest = snapshot.digest()
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    path = snapshots_dir / f"{digest}.{snapshot.mode}.json"
    text = json.dumps(
        json.loads(snapshot.canonical_json()), indent=2, sort_keys=True, ensure_ascii=False
    )
    path.write_text(text + "\n", encoding="utf-8", newline="\n")
    return digest, path


def run_demo_scout(out_dir: Path) -> DemoResult:
    fixture = FixtureSet.load(bundled(DEMO_FIXTURE))
    clock = FrozenClock(fixture.recorded_at)
    manifest = parse_scope(fixture.scope_yaml, now=clock.now())
    run_id = f"demo-{uuid.uuid4().hex}"
    journal_path = out_dir / "journal.sqlite"
    with SqliteJournal(journal_path, now=clock.now) as journal:
        journal.begin_run(run_id, "scout", "FIXTURE")
        gate = Gate(
            manifest,
            signed_in_tenant=fixture.manifest.tenant_id,
            journal=journal,
            clock=clock,
            run_id=run_id,
        )
        collector = Collector(
            manifest=manifest,
            gate=gate,
            transport=FixtureTransport(fixture),
            clock=clock,
            mode="FIXTURE",
            sleep=clock.advance,
        )
        snapshot = collector.run()
    digest, path = write_snapshot(snapshot, out_dir / "snapshots")
    return DemoResult(snapshot, digest, path, journal_path, run_id, gate.calls_used)


def render(result: DemoResult, out: FixtureConsole) -> None:
    snap = result.snapshot
    out.print(
        f"Replaying bundled fixture {DEMO_FIXTURE!r}; no network calls are made.", style="fns.muted"
    )
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
    out.print(f"digest sha256:{result.digest}", style="fns.highlight")
