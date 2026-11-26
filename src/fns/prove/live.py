"""``fns prove --live``: run the frozen probes against the lab, as the test identity.

Order matters for safety (M3 P5, ``docs/milestones/M3-live-plan.md``):

1. load the scope (expired means stop) and require a LIVE snapshot of its tenant;
2. get an ARM token pinned to the scope's tenant, then read who it belongs to:
   ``oid`` must be a test identity, and its ``appid`` must match that identity's
   ``app_id`` when the scope lists one (decision V4). Anything else stops here,
   before the first API call;
3. freeze the assertions, then run each probe through one gate under ``prove``
   that pins the signed-in principal. Identical requests (the same kind, target
   and action asked for two findings) are sent once;
4. hand the run to the verifier in its own process.

With ``--record`` the observations are also written, sanitized, as ``probes.json``
next to the scout recording of the same run.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Literal

from fns.adapters.azure.dataplane import DataPlaneTransport
from fns.adapters.azure.http import Transport
from fns.adapters.azure.live import HttpTransport
from fns.fixtures.sanitize import GUID_RE, PLACEHOLDER_RE
from fns.fixtures.wellknown import WELL_KNOWN_GUIDS
from fns.journal.sqlite import SqliteJournal
from fns.models.assertions import AssertionSet, ProbeObservation, ProbeSpec
from fns.models.contract import Contract
from fns.models.scope import ScopeManifest, load_scope
from fns.models.snapshot import Snapshot
from fns.probes.base import Probe, ProbeUnavailableError, observation
from fns.probes.data_read import DataReadProbe, DataTransport, RoutedProbe
from fns.probes.mock import RESULTS_FILE, MockResult, MockResults
from fns.probes.permissions import ArmPermissionsProbe
from fns.prove.run import ProveResult, Signer, prove
from fns.scope.credentials import PinnedTokens, SignedInIdentity, TokenProvider
from fns.scope.gate import Clock, Gate, SystemClock

MAX_ERROR_DETAIL: Final = 200


class LiveProveError(RuntimeError):
    """Live probes cannot start (wrong snapshot, wrong identity). Nothing was sent."""


class ProberNotAllowedError(LiveProveError):
    """The signed-in identity is not the scope's test identity (exit 4)."""


@dataclass(frozen=True, slots=True)
class LiveProve:
    result: ProveResult
    prober: SignedInIdentity
    recorded: Path | None
    omitted: tuple[str, ...]
    """Observations not written to the recording (not allowed/denied, or conflicting)."""


def check_prober(manifest: ScopeManifest, who: SignedInIdentity) -> None:
    ident = next((i for i in manifest.test_identities if str(i.object_id) == who.object_id), None)
    if ident is None:
        raise ProberNotAllowedError(
            f"signed in as object {who.object_id}, which is not a test identity in the scope"
        )
    if ident.app_id is not None and str(ident.app_id) != who.app_id:
        raise ProberNotAllowedError(
            f"the token's appid does not match the app_id of test identity {ident.name}"
        )


class SharedRequests:
    """Send each distinct (kind, target, action) once; reuse its answer for later specs.

    Probe ids include the finding, so two findings asking the same question freeze
    two probes. They get two observations, but the tenant sees one request.
    """

    def __init__(self, inner: Probe) -> None:
        self.inner = inner
        self.mode: Literal["LIVE", "FIXTURE"] = inner.mode
        self._seen: dict[tuple[str, str, str], ProbeObservation | ProbeUnavailableError] = {}
        self.sent = 0

    def observe(self, spec: ProbeSpec, finding_id: str) -> ProbeObservation:
        key = (spec.kind, spec.target.lower(), spec.action.lower())
        if key not in self._seen:
            self.sent += 1
            try:
                self._seen[key] = self.inner.observe(spec, finding_id)
            except ProbeUnavailableError as exc:
                self._seen[key] = exc
        first = self._seen[key]
        if isinstance(first, ProbeUnavailableError):
            raise ProbeUnavailableError(str(first))
        if first.probe_id == spec.id:
            return first
        return observation(
            spec,
            finding_id,
            mode=first.mode,
            outcome=first.outcome,
            detail=f"{first.detail} (same request as probe {first.probe_id[:12]}, sent once)",
            at=first.observed_at,
            http_status=first.http_status,
            request_id=first.request_id,
        )


def run_live_prove(
    contract: Contract,
    snapshot: Snapshot,
    scope_path: Path,
    out_dir: Path,
    *,
    record: Path | None = None,
    signer: Signer = "offline-test",
    identity: str = "unspecified",
    clock: Clock | None = None,
    tokens: PinnedTokens | None = None,
    arm_transport_factory: Callable[[TokenProvider], Transport] = HttpTransport,
    data_transport_factory: Callable[[TokenProvider], DataTransport] = DataPlaneTransport,
) -> LiveProve:
    clock = clock or SystemClock()
    manifest = load_scope(scope_path, now=clock.now())
    if snapshot.mode != "LIVE":
        raise LiveProveError("live probes need a LIVE snapshot (run fns scout first)")
    if snapshot.tenant_id != manifest.tenant_id:
        raise LiveProveError("the snapshot's tenant is not the scope's tenant")
    if record is not None:
        _check_record_dir(record)
    tokens = tokens or PinnedTokens(str(manifest.tenant_id))
    signed_in = tokens.signed_in_tenant()  # raises TenantMismatchError before any API call
    who = tokens.signed_in_identity()
    check_prober(manifest, who)

    arm = arm_transport_factory(tokens)
    data = data_transport_factory(tokens)

    def make_probe(journal: SqliteJournal, run_id: str) -> Probe:
        gate = Gate(
            manifest,
            signed_in_tenant=signed_in,
            journal=journal,
            clock=clock,
            run_id=run_id,
            signed_in_principal=who.object_id,
        )
        common = {"tenant_id": signed_in, "principal_id": who.object_id, "now": clock.now}
        perms = ArmPermissionsProbe(gate=gate, transport=arm, **common)  # type: ignore[arg-type]
        reads = DataReadProbe(
            gate=gate,
            transport=data,
            arm_transport=arm,
            manifest=manifest,
            **common,  # type: ignore[arg-type]
        )
        routed = RoutedProbe({"arm-permissions": perms, "data-read": reads}, mode="LIVE")
        return SharedRequests(routed)

    result = prove(
        contract, snapshot, make_probe, out_dir, now=clock.now, signer=signer, identity=identity
    )
    recorded: Path | None = None
    omitted: tuple[str, ...] = ()
    if record is not None:
        recorded, omitted = write_recording(
            record, result.assertions, result.probes.observations, clock.now()
        )
    return LiveProve(result, who, recorded, omitted)


def _check_record_dir(record: Path) -> None:
    if not record.joinpath("manifest.json").is_file():
        raise LiveProveError(
            f"{record.as_posix()} has no scout recording: run fns scout --record there first"
        )
    if record.joinpath(RESULTS_FILE).exists():
        raise LiveProveError(f"{record.as_posix()}/{RESULTS_FILE} exists; not overwriting it")


def _no_real_ids(text: str) -> None:
    bad = [
        g
        for g in GUID_RE.findall(text)
        if g.lower() not in WELL_KNOWN_GUIDS and not PLACEHOLDER_RE.match(g.lower())
    ]
    if bad:
        raise LiveProveError("the recording would contain a real GUID; not written")


def write_recording(
    record: Path,
    aset: AssertionSet,
    observations: tuple[ProbeObservation, ...],
    at: datetime,
) -> tuple[Path, tuple[str, ...]]:
    """Write ``probes.json``: kind, resource name, action, outcome, status, detail.

    Nothing else is kept: no request IDs, no principal, no timestamps per probe. The
    detail holds only the status and allowlisted error codes. Observations that are
    neither ``allowed`` nor ``denied`` cannot be replayed (``MockResult``) and are
    listed in ``omitted``; so are keys whose observations disagree.
    """
    specs = {s.id: s for a in aset.assertions for s in a.probes}
    by_key: dict[tuple[str, str, str], list[ProbeObservation]] = {}
    omitted: list[str] = []
    for obs in observations:
        spec = specs[obs.probe_id]
        key = (obs.kind, spec.target.rsplit("/", 1)[-1].lower(), spec.action)
        by_key.setdefault(key, []).append(obs)
    results: list[MockResult] = []
    for (kind, resource, action), group in sorted(by_key.items()):
        outcomes = {o.outcome for o in group}
        label = f"{kind} {action} on {resource}"
        if len(outcomes) != 1 or next(iter(outcomes)) not in ("allowed", "denied"):
            omitted.append(f"{label}: {', '.join(sorted(outcomes))}")
            continue
        first = group[0]
        detail = first.detail.split(" (same request as probe", 1)[0][:MAX_ERROR_DETAIL]
        results.append(
            MockResult(
                kind=first.kind,
                resource=resource,
                action=action,
                outcome=first.outcome,  # type: ignore[arg-type]
                http_status=first.http_status,
                detail=detail,
            )
        )
    doc = MockResults(
        format=1,
        label="FIXTURE",
        description=(
            f"Recorded from the lab by fns prove --live on {at.date().isoformat()}, sanitized: "
            "status and allowlisted error codes only; no request IDs, bodies or principals."
        ),
        results=tuple(results),
    )
    text = json.dumps(json.loads(doc.model_dump_json()), indent=2, sort_keys=True) + "\n"
    _no_real_ids(text)
    path = record / RESULTS_FILE
    path.write_text(text, encoding="utf-8", newline="\n")
    return path, tuple(omitted)
