"""Evaluate a contract against a snapshot: one finding per (item, operation).

M2 rule (docs/milestones/M2.md): the model can make a finding fail but never
pass. Decision table:

=============== ====================================== ============ ==============
item            model says                             verdict      coverage
=============== ====================================== ============ ==============
must_not_reach  reachable                              fail         modeled-only
must_not_reach  not reachable, nothing missing         inconclusive modeled-only
must_not_reach  not reachable, something not collected inconclusive not-assessed
must_still_do   allowed                                inconclusive modeled-only
must_still_do   not allowed, nothing missing           fail         modeled-only
must_still_do   not allowed, something not collected   inconclusive not-assessed
any             unresolved target or unknown semantics inconclusive not-assessed
=============== ====================================== ============ ==============
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from fns.contain import rbac
from fns.contain import semantics as sem
from fns.contain.closure import Closure, Derivation, Fact, SnapshotIndex, app_perm, controls
from fns.contain.resolve import resolve_identity, resolve_object, resolve_resource
from fns.exitcodes import ExitCode
from fns.models.contract import (
    ApplicationTarget,
    Contract,
    DirectoryTarget,
    ReachTarget,
    ResourceTarget,
    ServicePrincipalTarget,
)
from fns.models.evidence import CoverageState, Evidence, Finding, ItemKind, Outcome, Verdict
from fns.models.snapshot import Entity, Snapshot

MAX_PATHS: Final = 4
"""The shortest path plus up to three alternatives."""
EVIDENCE_SOURCE: Final = "fns.contain"


@dataclass(frozen=True, slots=True)
class HopCheck:
    """The RBAC (data) action a final hop rests on, at the scope it was granted for.

    M3 asks the platform about exactly this (rung 2) to refute or confirm the hop.
    """

    action: str
    scope: str
    data_plane: bool


@dataclass(frozen=True, slots=True)
class PathStep:
    rule: str
    text: str
    sources: tuple[str, ...] = ()
    check: HopCheck | None = None


@dataclass(frozen=True, slots=True)
class ReachPath:
    steps: tuple[PathStep, ...]
    assumptions: tuple[str, ...] = ()
    partial: bool = False
    """The grant covers only part of the target (a child scope, or owned objects)."""

    def sort_key(self) -> tuple[int, int, int, tuple[str, ...]]:
        """Shortest first; among equals, paths resting on fewer assumptions."""
        return (
            len(self.steps),
            len(self.assumptions),
            int(self.partial),
            tuple(s.text for s in self.steps),
        )

    def one_line(self) -> str:
        return " -> ".join(s.rule for s in self.steps if s.rule != "snapshot")


@dataclass(frozen=True, slots=True)
class _Hit:
    principal: str
    way: sem.Way
    premises: tuple[Fact, ...]
    text: str
    sources: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    partial: bool = False
    conditional: bool = False
    check: HopCheck | None = None


@dataclass(frozen=True, slots=True)
class ItemOutcome:
    finding: Finding
    paths: tuple[ReachPath, ...] = ()


@dataclass(frozen=True, slots=True)
class Summary:
    critical: int
    max_critical: int
    still_do_failed: int
    inconclusive: int
    max_inconclusive: int
    on_inconclusive: Literal["fail", "warn"]
    exit_code: int
    warning: str | None = None


@dataclass(frozen=True, slots=True)
class Evaluation:
    contract: Contract
    snapshot: Snapshot
    compromised: str | None
    outcomes: tuple[ItemOutcome, ...]
    summary: Summary


# -- reach queries -----------------------------------------------------------


def _requirements(way: sem.Way, target: Entity) -> tuple[bool, tuple[str, ...]]:
    """Does ``target``'s configuration allow ``way``? Unknown means assumed default."""
    notes: list[str] = []
    props = target.properties
    for req in way.requires:
        if req in {"kv-rbac-mode", "kv-access-policy-mode"}:
            if "enableRbacAuthorization" not in props:
                notes.append("the vault's permission model was not collected; assumes either")
                continue
            # Collected but null means Azure's default: access-policy mode.
            rbac_mode = props["enableRbacAuthorization"] is True
            if rbac_mode != (req == "kv-rbac-mode"):
                return False, ()
        elif req == "shared-key":
            value = target.properties.get("allowSharedKeyAccess")
            if value is False:
                return False, ()
            if "allowSharedKeyAccess" not in target.properties:
                notes.append(
                    "allowSharedKeyAccess was not collected; assumes Azure's default "
                    "(shared key allowed)"
                )
    return True, tuple(notes)


def _resource_hits(
    closure: Closure, semantics: sem.OperationSemantics, target: Entity
) -> list[_Hit]:
    ix = closure.index
    rtype = str(target.properties.get("resourceType", ""))
    hits: list[_Hit] = []
    for p in closure.controlled():
        eff = closure.effective(p)
        for way in semantics.ways_for(rtype):
            ok, assumptions = _requirements(way, target)
            if not ok:
                continue
            if way.kind == "accessPolicy":
                hits.extend(_policy_hits(closure, p, eff, way, semantics, target, assumptions))
                continue
            data = way.kind == "dataAction"
            for grant in closure.facts_of("rbac", eff):
                scope, _role_id, _assignment, condition = grant.args
                rel = rbac.scope_relation(scope, target.id)
                role = closure.role(grant)
                if rel is None or role is None:
                    continue
                action = next((a for a in way.values if role.permits(a, data=data)), None)
                if action is None:
                    continue
                at = scope if rel == "descendant" else target.id
                if ix.denied(eff, action, data=data, at=at):
                    continue
                notes = list(assumptions)
                if rel == "descendant":
                    notes.append(f"the grant is on {scope}, a child scope of the target")
                if way.note:
                    notes.append(way.note)
                hits.append(
                    _Hit(
                        p,
                        way,
                        (controls(p), *closure.membership(p, grant.principal), grant),
                        f"{role.name} allows {action} on {ix.name(target.id)}"
                        f" ({semantics.operation})",
                        assumptions=tuple(notes),
                        partial=rel == "descendant",
                        conditional=bool(condition),
                        check=HopCheck(action, at, data),
                    )
                )
    return hits


def _policy_hits(
    closure: Closure,
    p: str,
    eff: frozenset[str],
    way: sem.Way,
    semantics: sem.OperationSemantics,
    target: Entity,
    assumptions: tuple[str, ...],
) -> list[_Hit]:
    ix = closure.index
    out: list[_Hit] = []
    for edge in ix.access_policies.get(target.id, ()):
        granted = next((v for v in way.values if v in edge.secrets), None)
        if edge.src not in eff or granted is None:
            continue
        out.append(
            _Hit(
                p,
                way,
                (controls(p), *closure.membership(p, edge.src)),
                f"an access policy gives {ix.name(edge.src)} secrets/{granted} on "
                f"{ix.name(target.id)} ({semantics.operation})",
                sources=(ix.source(edge),),
                assumptions=assumptions,
            )
        )
    return out


def _directory_hits(closure: Closure, semantics: sem.OperationSemantics) -> list[_Hit]:
    ix = closure.index
    op = semantics.operation
    hits: list[_Hit] = []
    for p in closure.controlled():
        eff = closure.effective(p)
        perms = closure.app_perms(p)
        for way in semantics.ways:
            if way.kind == "appPerm":
                for value in way.values:
                    if value in perms:
                        hits.append(
                            _Hit(
                                p,
                                way,
                                (controls(p), app_perm(p, value)),
                                f"{value} allows {op} on any object in the tenant",
                            )
                        )
            elif way.kind == "dirRole":
                for f in closure.facts_of("dir-role", eff):
                    role, scope = f.args
                    if role not in way.values:
                        continue
                    hits.append(
                        _Hit(
                            p,
                            way,
                            (controls(p), *closure.membership(p, f.principal), f),
                            f"the directory role {ix.name(role)} allows {op}",
                            assumptions=(f"the role is scoped to {scope}",) if scope != "/" else (),
                            partial=scope != "/",
                        )
                    )
            elif way.kind == "ownedObjectPerm":
                owned = [
                    e
                    for e in ix.owns.get(p, ())
                    if ix.type_of(e.dst) in {"application", "servicePrincipal"}
                ]
                for value in way.values:
                    if value not in perms:
                        continue
                    for edge in owned:
                        hits.append(
                            _Hit(
                                p,
                                way,
                                (controls(p), app_perm(p, value)),
                                f"{ix.name(p)} owns {ix.name(edge.dst)}; {value} allows {op} "
                                "on objects it owns",
                                sources=(ix.source(edge),),
                                assumptions=("only on objects it owns (counts as reachable, D2)",),
                                partial=True,
                            )
                        )
    return hits


def _object_hits(
    closure: Closure, semantics: sem.OperationSemantics, target: Entity
) -> tuple[list[_Hit], list[str]]:
    """Hits on one application or service principal, and notes for the reasons.

    A service principal is also covered through its application: a credential on
    the application signs in as the service principal.
    """
    ix = closure.index
    op = semantics.operation
    covered = {target.id}
    if target.type == "servicePrincipal":
        covered.update(
            app for app, edges in ix.sps_of_app.items() if any(e.src == target.id for e in edges)
        )
    name = ix.name(target.id)
    hits: list[_Hit] = []
    notes: list[str] = []
    for p in closure.controlled():
        eff = closure.effective(p)
        perms = closure.app_perms(p)
        owned = [e for e in ix.owns.get(p, ()) if e.dst in covered]
        for way in semantics.ways:
            if way.kind == "appPerm":
                hits.extend(
                    _Hit(
                        p,
                        way,
                        (controls(p), app_perm(p, value)),
                        f"{value} allows {op} on {name} (and every other object in the tenant)",
                    )
                    for value in way.values
                    if value in perms
                )
            elif way.kind == "dirRole":
                for f in closure.facts_of("dir-role", eff):
                    role, scope = f.args
                    if role not in way.values or (scope != "/" and scope.strip("/") not in covered):
                        continue
                    hits.append(
                        _Hit(
                            p,
                            way,
                            (controls(p), *closure.membership(p, f.principal), f),
                            f"the directory role {ix.name(role)} allows {op} on {name}",
                        )
                    )
            elif way.kind == "ownedObjectPerm":
                held = [v for v in way.values if v in perms]
                for edge in owned:
                    if not held:
                        notes.append(
                            f"{ix.name(p)} owns {ix.name(edge.dst)} but holds neither "
                            f"{sem.APP_READWRITE_OWNEDBY} nor {sem.APP_READWRITE_ALL}, so an "
                            "app-only caller cannot use the ownership (one Graph grant away)"
                        )
                    hits.extend(
                        _Hit(
                            p,
                            way,
                            (controls(p), app_perm(p, value)),
                            f"{ix.name(p)} owns {ix.name(edge.dst)}; {value} allows {op} on "
                            "objects it owns",
                            sources=(ix.source(edge),),
                        )
                        for value in held
                    )
    return hits, sorted(set(notes))


_KIND: Final[dict[type, sem.TargetKind]] = {
    DirectoryTarget: "directory",
    ApplicationTarget: "application",
    ServicePrincipalTarget: "servicePrincipal",
}


def _unwind(closure: Closure, premises: tuple[Fact, ...]) -> list[Derivation]:
    seen: set[Fact] = set()
    out: list[Derivation] = []

    def visit(fact: Fact) -> None:
        if fact in seen:
            return
        seen.add(fact)
        d = closure.derivations[fact]
        for p in d.premises:
            visit(p)
        out.append(d)

    for f in premises:
        visit(f)
    return out


def _paths(closure: Closure, hits: list[_Hit]) -> tuple[ReachPath, ...]:
    paths: dict[tuple[PathStep, ...], ReachPath] = {}
    for hit in hits:
        unwound = [PathStep(d.rule, d.text, d.sources) for d in _unwind(closure, hit.premises)]
        steps = (*unwound, PathStep(hit.way.rule, hit.text, hit.sources, hit.check))
        path = ReachPath(steps, tuple(dict.fromkeys(hit.assumptions)), hit.partial)
        if steps not in paths or path.sort_key() < paths[steps].sort_key():
            paths[steps] = path
    return tuple(sorted(paths.values(), key=ReachPath.sort_key)[:MAX_PATHS])


def _gaps(closure: Closure, semantics: sem.OperationSemantics, target: Entity | None) -> list[str]:
    snapshot = closure.index.snapshot
    missing = {n.surface: n.reason for n in snapshot.coverage.not_collected}
    out: list[str] = []
    for surface in (*semantics.surfaces, *sem.GLOBAL_SURFACES):
        if (
            surface == sem.KV_ACCESS_POLICIES
            and target is not None
            and target.properties.get("enableRbacAuthorization") is True
        ):
            continue
        if surface in missing:
            out.append(f"{surface} not collected: {missing[surface]}")
    for run in snapshot.coverage.collectors:
        if run.status != "complete":
            codes = ", ".join(run.error_codes) or "no error code"
            out.append(f"collector {run.name} is {run.status} ({codes})")
    out.extend(sorted(closure.uncertain))
    return out


# -- findings ----------------------------------------------------------------


def _finding(
    contract: Contract,
    kind: ItemKind,
    target_key: str,
    op: str,
    verdict: Verdict,
    coverage: CoverageState,
    outcome: Outcome | None,
    reasons: list[str],
    rule: str = "reach",
    notes: str | None = None,
) -> Finding:
    evidence = (
        (
            Evidence(
                rung="modeled", outcome=outcome, source=f"{EVIDENCE_SOURCE}/{rule}", notes=notes
            ),
        )
        if outcome is not None
        else ()
    )
    return Finding.model_validate(
        {
            "contract": contract.contract,
            "item_kind": kind,
            "target": target_key,
            "operation": op,
            "verdict": verdict,
            "coverage": coverage,
            "evidence": evidence,
            "reasons": tuple(dict.fromkeys(r for r in reasons if r)),
        }
    )


def _evaluate_op(
    contract: Contract,
    closure: Closure | None,
    kind: ItemKind,
    item: ReachTarget,
    op: str,
    target: Entity | None,
    context: list[str],
) -> ItemOutcome:
    key = item.target_key

    def unassessed(reason: str) -> ItemOutcome:
        return ItemOutcome(
            _finding(
                contract,
                kind,
                key,
                op,
                "inconclusive",
                "not-assessed",
                "unknown",
                [reason, *context],
            )
        )

    if closure is None:
        return unassessed("the compromised identity could not be resolved")
    target_kind = _KIND.get(type(item), "resource")
    semantics = sem.lookup(target_kind, op)
    if semantics is None:
        return unassessed(f"unknown operation semantics: {target_kind} {op}")
    if target_kind == "directory":
        hits = _directory_hits(closure, semantics)
    elif target is None:
        return unassessed("the target could not be resolved")
    elif target_kind == "resource":
        rtype = str(target.properties.get("resourceType", ""))
        if not semantics.ways_for(rtype):
            return unassessed(f"unknown operation semantics: {op} on {rtype or 'this type'}")
        hits = _resource_hits(closure, semantics, target)
    else:
        hits, notes = _object_hits(closure, semantics, target)
        context = [*context, *notes]

    firm = [h for h in hits if not h.conditional]
    paths = _paths(closure, firm)
    gaps = _gaps(closure, semantics, target)
    if paths:
        best = paths[0]
        rule = best.steps[-1].rule
        summary = f"{len(paths)} path(s); shortest: {best.one_line()}"
        if kind == "must_not_reach":
            reasons = [f"reachable in the model: {summary}", *best.assumptions, *context]
            f = _finding(
                contract,
                kind,
                key,
                op,
                "fail",
                "modeled-only",
                "allowed",
                reasons,
                rule,
                best.one_line(),
            )
        else:
            reasons = [
                "allowed in the model; needs an observed success (M3)",
                summary,
                *best.assumptions,
                *context,
            ]
            f = _finding(
                contract,
                kind,
                key,
                op,
                "inconclusive",
                "modeled-only",
                "allowed",
                reasons,
                rule,
                best.one_line(),
            )
        return ItemOutcome(f, paths)

    if any(h.conditional for h in hits):
        gaps.append("only grants with ABAC conditions apply (conditions are not evaluated)")
    if gaps:
        lead = (
            "not reachable in the collected model, but it is incomplete"
            if kind == "must_not_reach"
            else "not allowed in the collected model, but it is incomplete"
        )
        f = _finding(
            contract,
            kind,
            key,
            op,
            "inconclusive",
            "not-assessed",
            "unknown",
            [lead, *gaps, *context],
        )
    elif kind == "must_not_reach":
        f = _finding(
            contract,
            kind,
            key,
            op,
            "inconclusive",
            "modeled-only",
            "denied",
            ["not reachable in the model; needs an observed denial (M3)", *context],
        )
    else:
        f = _finding(
            contract,
            kind,
            key,
            op,
            "fail",
            "modeled-only",
            "denied",
            ["nothing in the model grants this legitimate operation", *context],
        )
    return ItemOutcome(f)


def _summary(contract: Contract, outcomes: list[ItemOutcome]) -> Summary:
    findings = [o.finding for o in outcomes]
    critical = sum(f.verdict == "fail" and f.item_kind == "must_not_reach" for f in findings)
    still = sum(f.verdict == "fail" and f.item_kind == "must_still_do" for f in findings)
    inconclusive = sum(f.verdict == "inconclusive" for f in findings)
    b = contract.budget
    warning = None
    if critical > b.max_critical_reachable or still:
        code = ExitCode.CONTRACT_FAILED
    elif inconclusive > b.max_inconclusive:
        if contract.on_inconclusive == "fail":
            code = ExitCode.INCONCLUSIVE_OVER_BUDGET
        else:
            code = ExitCode.OK
            warning = (
                f"{inconclusive} inconclusive findings exceed max_inconclusive "
                f"{b.max_inconclusive}; passing only because on_inconclusive is warn"
            )
    else:
        code = ExitCode.OK
    return Summary(
        critical,
        b.max_critical_reachable,
        still,
        inconclusive,
        b.max_inconclusive,
        contract.on_inconclusive,
        int(code),
        warning,
    )


def evaluate(contract: Contract, snapshot: Snapshot) -> Evaluation:
    index = SnapshotIndex(snapshot)
    who = resolve_identity(snapshot, contract.assume_compromised)
    closure = Closure(index, who.entity.id) if who.entity is not None else None
    outcomes: list[ItemOutcome] = []
    items: list[tuple[ItemKind, ReachTarget]] = [
        *(("must_not_reach", i) for i in contract.must_not_reach),
        *(("must_still_do", i) for i in contract.must_still_do),
    ]
    for kind, item in items:
        context = [who.reason]
        target: Entity | None = None
        res = None
        if isinstance(item, ResourceTarget):
            res = resolve_resource(snapshot, item.resource)
        elif isinstance(item, ApplicationTarget):
            res = resolve_object(snapshot, "application", item.application)
        elif isinstance(item, ServicePrincipalTarget):
            res = resolve_object(snapshot, "servicePrincipal", item.service_principal)
        if res is not None:
            target = res.entity
            context.append(res.reason)
        for op in item.operations:
            outcomes.append(_evaluate_op(contract, closure, kind, item, op, target, context))
    return Evaluation(
        contract,
        snapshot,
        who.entity.id if who.entity is not None else None,
        tuple(outcomes),
        _summary(contract, outcomes),
    )
