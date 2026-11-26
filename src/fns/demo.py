"""``fns demo scout``: replay the bundled fixture through the real pipeline.

The demo uses the same scope gate, collector and journal as a live run. Only
the transport (fixture replay) and the clock (frozen at the fixture's
``recorded_at``) differ, so the output is deterministic and the short demo
scope expiry stays valid. Every line of output is labelled FIXTURE.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fns.console import FixtureConsole
from fns.fixtures.replay import FixtureSet, FixtureTransport, bundled
from fns.inventory.collector import Collector
from fns.journal.sqlite import SqliteJournal
from fns.models.scope import parse_scope
from fns.scope.gate import FrozenClock, Gate
from fns.summary import ScoutResult, render_summary, write_snapshot

DEMO_FIXTURE = "demo-scout"


def run_demo_scout(out_dir: Path, fixture_dir: Path | None = None) -> ScoutResult:
    """Replay the bundled set, or a recorded set from ``fixture_dir``."""
    fixture = FixtureSet.load(fixture_dir if fixture_dir is not None else bundled(DEMO_FIXTURE))
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
    return ScoutResult(snapshot, digest, path, journal_path, run_id, gate.calls_used)


def render(result: ScoutResult, out: FixtureConsole, source: str = DEMO_FIXTURE) -> None:
    out.print(f"Replaying fixture {source!r}; no network calls are made.", style="fns.muted")
    render_summary(result, out)
