"""Freeze a contain report into the assertions a ``fns prove`` run is judged by.

Runs before any probe. For each finding it decides which probes are worth running
and, for each modeled path, which probe results would refute it
(docs/milestones/M3.md, "The claim problem"):

- a path with an escalation hop cannot be refuted by a non-destructive probe;
- a current-state path whose final way grants the operation directly is refuted
  by a denied direct read, or by a denied permission check of its final action;
- an indirect final way (``kv-control-to-data``, ``listkeys-data``) is refuted only
  by a denied check of its own action.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Final

from fns.contain import semantics as sem
from fns.contain.closure import Closure, SnapshotIndex
from fns.contain.evaluate import DONE
from fns.contain.resolve import resolve_object, resolve_resource
from fns.models.assertions import (
    PROBE_RUNG,
    Assertion,
    AssertionSet,
    PathAssertion,
    ProbeKind,
    ProbePurpose,
    ProbeSpec,
    Thresholds,
    probe_id,
)
from fns.models.contract import Contract
from fns.models.evidence import Finding, Outcome
from fns.models.report import ContainReport, ReachPath
from fns.models.snapshot import Entity, Snapshot

DATA_READS: Final = frozenset({"secrets/get", "secrets/list", "blob/read"})
"""Contract operations a non-destructive data-plane read can observe (rung 3)."""

PERMISSIONS_OPERATION: Final = "arm:Microsoft.Authorization/permissions/read"

PIM_ELIGIBLE: Final = "pim-eligibility:eligible"
"""Open surface: the attacker controls a PIM-eligible principal, so an observed denial
today does not show the operation stays denied after activation."""

AGENT_ID_INHERITANCE: Final = "agent-id-inheritance:not-modeled"
"""Open surface: the attacker controls an Entra Agent ID object, and what an agent
identity inherits from its blueprint is not modeled (approved 2026-11-27)."""


def run_id_for(report: ContainReport, frozen_at: datetime) -> str:
    text = f"{report.digest()}|{frozen_at.isoformat()}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def freeze(
    contract: Contract,
    snapshot: Snapshot,
    report: ContainReport,
    *,
    frozen_at: datetime,
    run_id: str | None = None,
) -> AssertionSet:
    if report.snapshot_digest != snapshot.digest():
        raise ValueError("the report was not built from this snapshot")
    if report.contract_digest != contract.digest():
        raise ValueError("the report was not built from this contract")
    by_finding: dict[str, list[ReachPath]] = {}
    for p in report.paths:
        by_finding.setdefault(p.finding_id, []).append(p)
    surfaces = _closure_surfaces(snapshot, report.compromised)
    assertions = tuple(
        _assertion(f, by_finding.get(f.id, []), snapshot, surfaces) for f in report.findings
    )
    b = contract.budget
    return AssertionSet(
        version=1,
        mode=report.mode,
        run_id=run_id or run_id_for(report, frozen_at),
        contract=report.contract,
        contract_digest=report.contract_digest,
        snapshot_digest=report.snapshot_digest,
        report_digest=report.digest(),
        tenant_id=report.tenant_id,
        compromised=report.compromised,
        compromised_name=report.compromised_name,
        thresholds=Thresholds(
            max_critical_reachable=b.max_critical_reachable,
            max_inconclusive=b.max_inconclusive,
            on_inconclusive=contract.on_inconclusive,
        ),
        frozen_at=frozen_at,
        assertions=assertions,
    )


class _Probes:
    def __init__(self, finding_id: str) -> None:
        self.finding_id = finding_id
        self.specs: dict[str, ProbeSpec] = {}

    def add(
        self,
        kind: ProbeKind,
        purpose: ProbePurpose,
        target: str,
        action: str,
        *,
        data_plane: bool = False,
    ) -> str:
        pid = probe_id(self.finding_id, kind, target, action)
        if pid not in self.specs:
            self.specs[pid] = ProbeSpec(
                id=pid,
                kind=kind,
                rung=PROBE_RUNG[kind],
                purpose=purpose,
                target=target,
                action=action,
                data_plane=data_plane,
                scope_operation=PERMISSIONS_OPERATION if kind == "arm-permissions" else None,
            )
        return pid


_KINDS: dict[str, sem.TargetKind] = {
    "directory": "directory",
    "application": "application",
    "service_principal": "servicePrincipal",
}
"""Finding target prefix -> semantics target kind. Only resources get probes in M3."""


def _resource(snapshot: Snapshot, finding: Finding) -> Entity | None:
    kind, _, ref = finding.target.partition(":")
    if kind != "resource":
        return None
    return resolve_resource(snapshot, ref).entity


def _object_id(snapshot: Snapshot, finding: Finding) -> str | None:
    """The object ID of an application or service principal target, if it resolves."""
    kind, _, ref = finding.target.partition(":")
    entity_kind = {"application": "application", "service_principal": "servicePrincipal"}.get(kind)
    if entity_kind is None:
        return None
    entity = resolve_object(snapshot, entity_kind, ref).entity
    return None if entity is None else entity.id.lower()


def _closure_surfaces(snapshot: Snapshot, compromised: str | None) -> tuple[str, ...]:
    """Open surfaces from what the attacker controls: PIM eligibility (activation is
    not modeled) and Agent ID objects (inheritance is not modeled)."""
    if compromised is None:
        return ()
    c = Closure(SnapshotIndex(snapshot), compromised)
    return (
        *((PIM_ELIGIBLE,) if c.eligibility else ()),
        *((AGENT_ID_INHERITANCE,) if c.agent_ids else ()),
    )


def _assertion(
    finding: Finding,
    paths: list[ReachPath],
    snapshot: Snapshot,
    surfaces: tuple[str, ...] = (),
) -> Assertion:
    probes = _Probes(finding.id)
    target = _resource(snapshot, finding)
    direct: list[str] = []
    semantics = sem.lookup(
        _KINDS.get(finding.target.partition(":")[0], "resource"), finding.operation
    )
    if target is not None and semantics is not None:
        rtype = str(target.properties.get("resourceType", ""))
        if finding.operation in DATA_READS:
            direct.append(probes.add("data-read", "direct", target.id, finding.operation))
        for way in semantics.ways_for(rtype):
            if way.rule in sem.INDIRECT_WAYS or way.kind not in {"action", "dataAction"}:
                continue
            for value in way.values:
                direct.append(
                    probes.add(
                        "arm-permissions",
                        "direct",
                        target.id,
                        value,
                        data_plane=way.kind == "dataAction",
                    )
                )

    path_assertions = []
    for p in sorted(paths, key=lambda p: p.rank):
        final = p.steps[-1]
        escalates = any(s.rule not in sem.NON_ESCALATION_RULES for s in p.steps[:-1])
        refuted_by: list[str] = []
        if not escalates:
            if final.check is not None:
                refuted_by.append(
                    probes.add(
                        "arm-permissions",
                        "hop",
                        final.check.scope,
                        final.check.action,
                        data_plane=final.check.data_plane,
                    )
                )
            if final.rule not in sem.INDIRECT_WAYS:
                refuted_by.extend(pid for pid in direct if probes.specs[pid].kind == "data-read")
        path_assertions.append(
            PathAssertion(
                path_id=p.id,
                summary=" -> ".join(s.rule for s in p.steps if s.rule != "snapshot"),
                refuted_by=tuple(refuted_by),
            )
        )

    return Assertion(
        finding_id=finding.id,
        item_kind=finding.item_kind,
        target=finding.target,
        operation=finding.operation,
        modeled_outcome=_modeled(finding),
        modeled_reasons=finding.reasons,
        paths=tuple(path_assertions),
        probes=tuple(probes.specs.values()),
        open_surfaces=(
            *_open_surfaces(snapshot, semantics, target),
            *surfaces,
        ),
        target_object_id=_object_id(snapshot, finding),
    )


def _modeled(finding: Finding) -> Outcome:
    for e in finding.evidence:
        if e.rung == "modeled":
            return e.outcome
    return "unknown"


def _open_surfaces(
    snapshot: Snapshot, semantics: sem.OperationSemantics | None, target: Entity | None
) -> tuple[str, ...]:
    """Uncollected surfaces that could add reach for this operation; an unknown
    operation leaves every uncollected surface open."""
    missing = {n.surface for n in snapshot.coverage.not_collected}
    wanted = (
        set(missing) if semantics is None else {*semantics.surfaces, *sem.GLOBAL_SURFACES} & missing
    )
    if target is not None and target.properties.get("enableRbacAuthorization") is True:
        wanted.discard(sem.KV_ACCESS_POLICIES)
    out = set(wanted)
    out.update(
        f"collector:{run.name}" for run in snapshot.coverage.collectors if run.status not in DONE
    )
    return tuple(sorted(out))
