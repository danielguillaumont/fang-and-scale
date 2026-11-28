"""Turn an :class:`~fns.contain.evaluate.Evaluation` into a :class:`ContainReport`."""

from __future__ import annotations

from datetime import datetime

from fns.contain import semantics as sem
from fns.contain.evaluate import Evaluation
from fns.models.evidence import Finding
from fns.models.report import (
    ContainReport,
    HopCheck,
    PathStep,
    ReachPath,
    ReportSummary,
    path_id,
)


def build_report(
    evaluation: Evaluation, *, generated_at: datetime, tool_version: str
) -> ContainReport:
    findings: list[Finding] = []
    paths: list[ReachPath] = []
    for outcome in evaluation.outcomes:
        f = outcome.finding
        ranked = [
            ReachPath(
                id=path_id(f.id, tuple(s.text for s in p.steps)),
                finding_id=f.id,
                rank=rank,
                steps=tuple(
                    PathStep(
                        rule=s.rule,
                        text=s.text,
                        sources=s.sources,
                        check=None
                        if s.check is None
                        else HopCheck(
                            action=s.check.action,
                            scope=s.check.scope,
                            data_plane=s.check.data_plane,
                        ),
                    )
                    for s in p.steps
                ),
                assumptions=p.assumptions,
                partial=p.partial,
            )
            for rank, p in enumerate(outcome.paths)
        ]
        paths.extend(ranked)
        if ranked:
            best = ranked[0].id
            evidence = tuple(
                e.model_copy(update={"path_id": best}) if e.outcome == "allowed" else e
                for e in f.evidence
            )
            f = Finding.model_validate({**f.model_dump(), "evidence": evidence})
        findings.append(f)
    s = evaluation.summary
    return ContainReport(
        version=1,
        mode=evaluation.snapshot.mode,
        contract=evaluation.contract.contract,
        contract_digest=evaluation.contract.digest(),
        snapshot_digest=evaluation.snapshot.digest(),
        tenant_id=str(evaluation.snapshot.tenant_id),
        semantics_version=sem.SEMANTICS_VERSION,
        compromised=evaluation.compromised,
        compromised_name=_name(evaluation),
        generated_at=generated_at,
        tool_version=tool_version,
        findings=tuple(findings),
        paths=tuple(paths),
        front_doors=evaluation.front_doors,
        summary=ReportSummary(
            critical=s.critical,
            max_critical_reachable=s.max_critical,
            still_do_failed=s.still_do_failed,
            inconclusive=s.inconclusive,
            max_inconclusive=s.max_inconclusive,
            on_inconclusive=s.on_inconclusive,
            exit_code=s.exit_code,  # type: ignore[arg-type]
            warning=s.warning,
            unaccepted_inconclusive=s.unaccepted_inconclusive,
        ),
    )


def _name(evaluation: Evaluation) -> str | None:
    if evaluation.compromised is None:
        return None
    for e in evaluation.snapshot.entities:
        if e.id == evaluation.compromised:
            return e.display_name
    return None
