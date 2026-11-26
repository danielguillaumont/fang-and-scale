"""``fns scout``: live, read-only collection against the tenant in ``scope.yaml``.

Order matters for safety:

1. load and validate the scope manifest (expired means stop);
2. get an ARM token pinned to the manifest's tenant and check its ``tid``
   (CLAUDE.md rule 3): a mismatch aborts before the first API call;
3. every request then goes through the gate, the journal and the read-only
   HTTPS transport; with ``--record`` responses are also sanitized to disk.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from pathlib import Path

from fns.adapters.azure.http import Transport
from fns.adapters.azure.live import HttpTransport
from fns.fixtures.recorder import Recorder
from fns.inventory.collector import Collector
from fns.journal.sqlite import SqliteJournal
from fns.models.scope import load_scope
from fns.scope.credentials import PinnedTokens, TokenProvider
from fns.scope.gate import Clock, Gate, SystemClock
from fns.summary import ScoutResult, write_snapshot


def run_live_scout(
    scope_path: Path,
    out_dir: Path,
    *,
    record: Path | None = None,
    clock: Clock | None = None,
    tokens: PinnedTokens | None = None,
    transport_factory: Callable[[TokenProvider], Transport] = HttpTransport,
    sleep: Callable[[float], None] = time.sleep,
) -> ScoutResult:
    clock = clock or SystemClock()
    manifest = load_scope(scope_path, now=clock.now())
    tenant = str(manifest.tenant_id)
    tokens = tokens or PinnedTokens(tenant)
    signed_in = tokens.signed_in_tenant()  # raises TenantMismatchError before any API call

    transport: Transport = transport_factory(tokens)
    recorder: Recorder | None = None
    if record is not None:
        recorder = Recorder(
            transport, record, name=record.name, tenant_id=tenant, recorded_at=clock.now()
        )
        transport = recorder

    run_id = f"scout-{uuid.uuid4().hex}"
    journal_path = out_dir / "journal.sqlite"
    with SqliteJournal(journal_path, now=clock.now) as journal:
        journal.begin_run(run_id, "scout", "LIVE")
        gate = Gate(
            manifest, signed_in_tenant=signed_in, journal=journal, clock=clock, run_id=run_id
        )
        collector = Collector(
            manifest=manifest,
            gate=gate,
            transport=transport,
            clock=clock,
            mode="LIVE",
            sleep=sleep,
        )
        snapshot = collector.run()
    digest, path = write_snapshot(snapshot, out_dir / "snapshots")
    fixture_path = None
    if recorder is not None:
        fixture_path = recorder.finalize(scope_path.read_text(encoding="utf-8"))
    return ScoutResult(snapshot, digest, path, journal_path, run_id, gate.calls_used, fixture_path)
