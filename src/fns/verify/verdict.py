"""Verdicts from frozen assertions and probe observations (docs/milestones/M3.md).

Independent of the reach engine: the verifier never re-runs the model. It
judges each assertion by the rules frozen into it:

- ``must_not_reach`` passes only with an observed denial of the operation, every
  modeled path refuted, and no open coverage surface (E1);
- a path that is not refuted keeps the item failing, on the evidence that still
  supports it; a direct denial is reported, and attached as context, never as if
  it settled the path;
- ``must_still_do`` passes only with an observed success.

Every probe result of an assertion ends up in its finding. Results that the
verdict rests on are supporting evidence. Every other result that came back
``allowed`` or ``denied`` is attached with ``role="context"``. Coverage and the
model's checks look at supporting evidence only, so context can never change a
verdict, a coverage state or an exit code (2026-11-26 decision).
"""

from __future__ import annotations

from typing import Literal

from fns.models.assertions import Assertion, ProbeObservation, StrikeObservation, Thresholds
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
        self.used: set[str] = set()

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
        picked = [p for p in pids if self.outcome(p) in ({only} if only else {"allowed", "denied"})]
        self.used.update(picked)
        return [self.evidence(p) for p in picked]

    def context(self) -> list[Evidence]:
        """Every other probe that came back allowed or denied, marked as context."""
        return [
            self.evidence(p.id).model_copy(update={"role": "context"})
            for p in sorted(self.a.probes, key=lambda p: p.id)
            if p.id not in self.used and self.outcome(p.id) in {"allowed", "denied"}
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
    evidence = [*evidence, *j.context()]
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


STRIKE_SOURCE = "fns.strike/after-harden"
VERDICT_RANK: dict[str, int] = {"fail": 0, "inconclusive": 1, "pass": 2}
"""Higher is looser. Strike evidence may only keep a verdict or lower its rank."""


class GuardrailError(AssertionError):
    """Strike evidence would have moved a finding toward pass (must never happen)."""


def with_strikes(f: Finding, strikes: list[tuple[StrikeObservation, str]]) -> Finding:
    """Add after-harden strike observations to a judged finding (D6, 2026-11-27).

    The guardrail: verdicts may only gain evidence or become stricter, never looser.

    - A denied attempt is attached as ``context``: it settles nothing, so the
      verdict, coverage and gap stay exactly as judged from the probes.
    - A successful attempt against a ``must_not_reach`` item is supporting
      evidence that the operation is reachable: the finding fails.
    - A successful attempt on a ``must_still_do`` item is context only.
    """
    if not strikes:
        return f
    added: list[Evidence] = []
    succeeded: list[StrikeObservation] = []
    for o, sha in sorted(strikes, key=lambda x: (x[0].write_key, x[1])):
        e = Evidence(
            rung="observed",
            outcome=o.outcome,
            source=STRIKE_SOURCE,
            artifact_digest=sha,
            observed_at=o.observed_at,
            notes=f"{o.write_key}: HTTP {o.http_status}"[:500],
        )
        if o.outcome == "allowed" and f.item_kind == "must_not_reach":
            succeeded.append(o)
            added.append(e)
        else:
            added.append(e.model_copy(update={"role": "context"}))
    data = f.model_dump()
    data["evidence"] = [*f.evidence, *added]
    if succeeded:
        names = ", ".join(sorted({o.strike for o in succeeded}))
        data["verdict"] = "fail"
        data["gap"] = f.gap if f.verdict == "fail" else None
        data["reasons"] = [
            f"an after-harden strike attempt succeeded ({names}; observed)",
            *f.reasons,
        ]
        data["coverage"] = coverage_for([e for e in data["evidence"] if e.role is None])
    new = Finding.model_validate(data)
    if VERDICT_RANK[new.verdict] > VERDICT_RANK[f.verdict]:
        raise GuardrailError(f"strike evidence moved {f.target} {f.operation} toward pass")
    return new


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
