"""Verdicts from frozen assertions and probe observations (docs/milestones/M3.md).

Independent of the reach engine: the verifier never re-runs the model. It
judges each assertion by the rules frozen into it:

- ``must_not_reach`` passes only with an observed denial of the operation, every
  modeled path refuted, and no open coverage surface (E1);
- a path that is not refuted keeps the item failing, on the evidence that still
  supports it; a direct denial is reported but never attached as if it settled
  the path;
- ``must_still_do`` passes only with an observed success.
"""

from __future__ import annotations

from typing import Literal

from fns.models.assertions import Assertion, ProbeObservation, Thresholds
from fns.models.bundle import BundleSummary
from fns.models.evidence import RUNG_ORDER, CoverageState, Evidence, Finding, Gap, Verdict

Obs = dict[str, tuple[ProbeObservation, str]]
MODEL_SOURCE = "frozen-assertions/fns.contain"

_COVERAGE: dict[str, CoverageState] = {
    "modeled": "modeled-only",
    "evaluated": "evaluated-only",
    "observed": "verified",
    "logged": "verified",
}


def coverage_for(evidence: list[Evidence]) -> CoverageState:
    results = [e for e in evidence if e.outcome in {"allowed", "denied"}]
    if not results:
        return "not-assessed"
    return _COVERAGE[max(results, key=lambda e: RUNG_ORDER[e.rung]).rung]


def _combined(outcomes: list[str]) -> Literal["allowed", "denied"] | None:
    """Several probes for one claim (e.g. two data actions that each grant the
    operation): allowed if any is allowed, denied only if every one is denied."""
    if "allowed" in outcomes:
        return "allowed"
    if outcomes and all(o == "denied" for o in outcomes):
        return "denied"
    return None


class _Judge:
    def __init__(self, a: Assertion, obs: Obs) -> None:
        self.a = a
        self.obs = obs
        self.spec = {p.id: p for p in a.probes}

    def outcome(self, pid: str) -> str:
        o = self.obs.get(pid)
        return o[0].outcome if o else "not-run"

    def evidence(self, pid: str) -> Evidence:
        o, sha = self.obs[pid]
        s = self.spec[pid]
        name = s.target.rsplit("/", 1)[-1]
        return Evidence(
            rung=o.rung,
            outcome=o.outcome,
            source=f"fns.probes/{s.kind}",
            artifact_digest=sha,
            observed_at=o.observed_at,
            notes=f"{s.purpose}: {s.action} on {name}; {o.detail}"[:500],
        )

    def direct(self, kind: str) -> list[str]:
        return [p.id for p in self.a.probes if p.purpose == "direct" and p.kind == kind]

    def results(self, pids: list[str], *, only: str | None = None) -> list[Evidence]:
        return [
            self.evidence(p)
            for p in pids
            if self.outcome(p) in ({only} if only else {"allowed", "denied"})
        ]


def judge(a: Assertion, obs: Obs, contract: str) -> Finding:
    j = _Judge(a, obs)
    modeled = Evidence(rung="modeled", outcome=a.modeled_outcome, source=MODEL_SOURCE)
    d_obs_ids, d_eval_ids = j.direct("data-read"), j.direct("arm-permissions")
    d_obs = _combined([j.outcome(p) for p in d_obs_ids if j.outcome(p) != "not-run"])
    d_eval = _combined([j.outcome(p) for p in d_eval_ids if j.outcome(p) != "not-run"])
    model_note = f"model: {a.modeled_reasons[0]}" if a.modeled_reasons else "model: no reasons"
    verdict: Verdict
    gap: Gap | None = None
    reasons: list[str] = []

    if a.item_kind == "must_not_reach":
        # Paths exist only where the model found the operation reachable.
        unrefuted = [
            p
            for p in a.paths
            if a.modeled_outcome == "allowed"
            and not any(j.outcome(r) == "denied" for r in p.refuted_by)
        ]
        if d_obs == "allowed":
            verdict = "fail"
            evidence = [modeled, *j.results(d_obs_ids), *j.results(d_eval_ids)]
            reasons.append("the operation succeeded when probed (observed)")
            if d_eval == "denied":
                gap = "platform-gap"
                reasons.append("the platform said it would be denied (platform-gap)")
        elif d_eval == "allowed" and d_obs != "denied":
            verdict = "fail"
            evidence = [modeled, *j.results(d_eval_ids, only="allowed")]
            reasons.append("the platform lists a granting action for the identity (evaluated)")
        elif unrefuted:
            verdict = "fail"
            confirming = [r for p in unrefuted for r in p.refuted_by]
            evidence = [modeled, *j.results(sorted(set(confirming)), only="allowed")]
            if d_obs == "denied":
                reasons.append(
                    "the operation itself was denied when probed, but escalation paths remain"
                )
            for p in unrefuted:
                why = (
                    "not refutable by a non-destructive probe"
                    if not p.refuted_by
                    else "its probes did not refute it"
                )
                reasons.append(f"path {p.summary}: {why}")
        else:
            refuting = [r for p in a.paths for r in p.refuted_by if j.outcome(r) == "denied"]
            evidence = [
                modeled,
                *j.results(d_obs_ids),
                *j.results(d_eval_ids),
                *j.results(sorted(set(refuting) - set(d_obs_ids) - set(d_eval_ids))),
            ]
            if d_obs == "denied" and not a.open_surfaces:
                verdict = "pass"
                reasons.append("denied when probed (observed), and every modeled path is refuted")
                if a.modeled_outcome == "allowed":
                    gap = "model-gap"
                    reasons.append("the model said reachable (model-gap)")
            elif d_obs == "denied":
                verdict = "inconclusive"
                reasons.append(
                    "denied when probed, but not collected: " + ", ".join(a.open_surfaces)
                )
            else:
                verdict = "inconclusive"
                reasons.append("needs an observed denial of the operation (rung 3)")
    else:
        all_direct = d_obs_ids + d_eval_ids
        evidence = [modeled, *j.results(all_direct)]
        if d_obs == "allowed":
            verdict = "pass"
            reasons.append("succeeded when probed (observed)")
        elif d_obs == "denied":
            verdict = "fail"
            reasons.append("denied when probed (observed)")
        elif d_eval == "denied":
            verdict = "fail"
            reasons.append("the platform lists no granting action for the identity (evaluated)")
        elif d_eval == "allowed":
            verdict = "inconclusive"
            reasons.append("allowed when evaluated; needs an observed success (rung 3)")
        elif a.modeled_outcome == "denied":
            verdict = "fail"
            reasons.append("nothing in the model grants it, and no probe ran")
        else:
            verdict = "inconclusive"
            reasons.append("no probe result; needs an observed success (rung 3)")

    not_run = [p for p in a.probes if j.outcome(p.id) == "not-run"]
    if not_run:
        reasons.append(f"{len(not_run)} probe(s) did not run")
    reasons.append(model_note)
    coverage = coverage_for(evidence)
    if coverage == "not-assessed":
        verdict = "inconclusive"
        gap = None
    return Finding.model_validate(
        {
            "id": a.finding_id,
            "contract": contract,
            "item_kind": a.item_kind,
            "target": a.target,
            "operation": a.operation,
            "verdict": verdict,
            "coverage": coverage,
            "evidence": evidence,
            "reasons": reasons,
            "gap": gap,
        }
    )


def summarize(findings: list[Finding], t: Thresholds) -> BundleSummary:
    critical = sum(f.item_kind == "must_not_reach" and f.verdict == "fail" for f in findings)
    still_do_failed = sum(f.item_kind == "must_still_do" and f.verdict == "fail" for f in findings)
    inconclusive = sum(f.verdict == "inconclusive" for f in findings)
    passed = sum(f.verdict == "pass" for f in findings)
    over = inconclusive > t.max_inconclusive
    exit_code: Literal[0, 1, 3]
    if critical > t.max_critical_reachable or still_do_failed:
        exit_code = 1
    elif over and t.on_inconclusive == "fail":
        exit_code = 3
    else:
        exit_code = 0
    warning = (
        f"{inconclusive} inconclusive (max {t.max_inconclusive})"
        if over and t.on_inconclusive == "warn"
        else None
    )
    return BundleSummary(
        passed=passed,
        critical=critical,
        still_do_failed=still_do_failed,
        inconclusive=inconclusive,
        exit_code=exit_code,
        warning=warning,
    )
