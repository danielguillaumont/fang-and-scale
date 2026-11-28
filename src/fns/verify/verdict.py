"""Verdicts from frozen assertions and probe observations (docs/milestones/M3.md).

Independent of the reach engine: the verifier never re-runs the model. It
judges each assertion by the rules frozen into it:

- ``must_not_reach`` passes only with an observed denial of the operation, every
  modeled path refuted, and no open coverage surface (E1);
- a path that is not refuted keeps the item failing, on the evidence that still
  supports it; a direct denial is reported, and attached as context, never as if
  it settled the path;
- ``must_still_do`` passes only with an observed success.

An after-harden strike denial counts like an observed probe denial only when it is
a *counting denial* (option B, approved 2026-11-27; :func:`not_counting`): LIVE,
D-2 to D-5, HTTP 403, on the item's exact operation and object, and never on
``directory:tenant roleAssignments/write``. It enters :func:`judge` in the
observed-denial slot, so ``pass`` keeps every other requirement. Every other strike
result is context, or fails the finding (:func:`with_strikes`).

Every probe result of an assertion ends up in its finding. Results that the
verdict rests on are supporting evidence. Every other result that came back
``allowed`` or ``denied`` is attached with ``role="context"``. Coverage and the
model's checks look at supporting evidence only, so context can never change a
verdict, a coverage state or an exit code (2026-11-26 decision).
"""

from __future__ import annotations

from typing import Final, Literal

from fns.models.assertions import Assertion, ProbeObservation, StrikeObservation, Thresholds
from fns.models.budget import unaccepted_inconclusive
from fns.models.bundle import BundleSummary
from fns.models.evidence import RUNG_ORDER, CoverageState, Evidence, Finding, Gap, Verdict

Obs = dict[str, tuple[ProbeObservation, str]]
Strikes = list[tuple[StrikeObservation, str]]
MODEL_SOURCE = "frozen-assertions/fns.contain"
STRIKE_SOURCE = "fns.strike/after-harden"

COUNTING_STATUS: Final = 403
"""The probes' rule (V5): only a 403 is a denial. A 401 can be an expired or wrong
token, so it says nothing about the request (approved 2026-11-27)."""
COUNTING: Final[dict[str, tuple[str, frozenset[str], str]]] = {
    "graph:POST /applications/{id}/addPassword": (
        "credentials/update",
        frozenset({"D-2", "D-3"}),
        "application",
    ),
    "graph:POST /applications/{id}/owners/$ref": (
        "owners/update",
        frozenset({"D-4", "D-5"}),
        "application",
    ),
    "arm:Microsoft.Storage/storageAccounts/listKeys/action": (
        "listKeys",
        frozenset({"D-6", "D-7"}),
        "resource",
    ),
}
"""Option B's exact-operation table: a planned write's operation, the one contract
operation it observes, the strikes that may make it, and the kind of item it is
for. ``listKeys`` (D-6, D-7) was added on 2026-11-27. Held here and not imported
from ``fns.strike``: the verifier's rule stays put when the strike engine changes."""
NEVER_COUNTS: Final = frozenset({("directory:tenant", "roleAssignments/write")})
"""SD3: no direct attempt is possible, so nothing may stand in for one."""


def not_counting(o: StrikeObservation, a: Assertion, *, live: bool) -> str | None:
    """Why ``o`` is not a counting denial for ``a``, or None if it is one."""
    row = COUNTING.get(o.request_operation or "")
    checks = (
        (live and o.mode == "LIVE", "not LIVE: FIXTURE never counts"),
        (a.item_kind == "must_not_reach", "not a must_not_reach item"),
        ((a.target, a.operation) not in NEVER_COUNTS, "roleAssignments/write never counts (SD3)"),
        ((o.target, o.operation) == (a.target, a.operation), "observes another item"),
        (o.outcome == "denied", "not a denial"),
        (o.http_status == COUNTING_STATUS, f"HTTP {o.http_status}, not 403"),
        (row is not None, "not a write in the exact-operation table"),
        (row is not None and row[0] == a.operation, "not the item's exact operation"),
        (row is not None and o.strike in row[1], f"{o.strike} does not make that request"),
        (
            row is not None and a.target.partition(":")[0] == row[2],
            f"not an item of the kind {row[2] if row else '?'} requests",
        ),
        (
            a.target_object_id is not None and o.request_object_id == a.target_object_id,
            "not the item's exact object",
        ),
    )
    return next((why for ok, why in checks if not ok), None)


def counting_denials(a: Assertion, strikes: Strikes, *, live: bool) -> Strikes:
    return sorted(
        (s for s in strikes if not_counting(s[0], a, live=live) is None),
        key=lambda s: (s[0].write_key, s[1]),
    )


def strike_evidence(o: StrikeObservation, sha: str) -> Evidence:
    return Evidence(
        rung="observed",
        outcome=o.outcome,
        source=STRIKE_SOURCE,
        artifact_digest=sha,
        observed_at=o.observed_at,
        notes=f"{o.write_key}: HTTP {o.http_status}"[:500],
    )


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


def judge(a: Assertion, obs: Obs, contract: str, counting: Strikes | None = None) -> Finding:
    """Judge one assertion. ``counting`` holds only counting denials
    (:func:`counting_denials`); they fill the observed-denial slot."""
    counting = counting or []
    j = _Judge(a, obs)
    modeled = Evidence(rung="modeled", outcome=a.modeled_outcome, source=MODEL_SOURCE)
    d_obs_ids, d_eval_ids = j.direct("data-read"), j.direct("arm-permissions")
    probe_obs = [j.outcome(p) for p in d_obs_ids if j.outcome(p) != "not-run"]
    d_obs = _combined([*probe_obs, *("denied" for _ in counting)])
    by_probe = _combined(probe_obs) == "denied"
    struck = ", ".join(sorted({o.strike for o, _ in counting}))
    denied_how = "when probed" if by_probe else f"by an after-harden strike ({struck})"
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
                    f"the operation itself was denied {denied_how}, but escalation paths remain"
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
                *(strike_evidence(o, sha) for o, sha in counting),
            ]
            if d_obs == "denied" and not a.open_surfaces:
                verdict = "pass"
                reasons.append(f"denied {denied_how} (observed), and every modeled path is refuted")
                if a.modeled_outcome == "allowed":
                    gap = "model-gap"
                    reasons.append("the model said reachable (model-gap)")
            elif d_obs == "denied":
                verdict = "inconclusive"
                reasons.append(
                    f"denied {denied_how}, but not collected: " + ", ".join(a.open_surfaces)
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


VERDICT_RANK: dict[str, int] = {"fail": 0, "inconclusive": 1, "pass": 2}
"""Higher is looser. Strike evidence may only keep a verdict or lower its rank."""


class GuardrailError(AssertionError):
    """Strike evidence moved a finding toward pass other than through a counting
    denial (must never happen)."""


def judge_with_strikes(
    a: Assertion, obs: Obs, contract: str, strikes: Strikes, *, live: bool
) -> Finding:
    """Judge an assertion with its after-harden strike observations (option B).

    The guardrail, narrowed on 2026-11-27: a strike may move a finding toward
    ``pass`` only through a counting denial, and only where the probe rules, given
    that denial, pass it. The finding is judged twice, without strikes and with the
    counting denials; if the result is looser than the first, every strike it rests
    on is checked again, or :class:`GuardrailError` is raised.
    """
    baseline = judge(a, obs, contract)
    counting = counting_denials(a, strikes, live=live)
    f = judge(a, obs, contract, counting) if counting else baseline
    used = {e.artifact_digest for e in f.evidence if e.source == STRIKE_SOURCE}
    new = with_strikes(f, [s for s in strikes if s[1] not in used])
    if VERDICT_RANK[new.verdict] > VERDICT_RANK[baseline.verdict]:
        resting = [s for s in strikes if s[1] in used]
        if not resting or any(not_counting(o, a, live=live) for o, _ in resting):
            raise GuardrailError(
                f"strike evidence moved {a.target} {a.operation} toward pass "
                "without a counting denial"
            )
    return new


def with_strikes(f: Finding, strikes: Strikes) -> Finding:
    """Add the strike observations that are not counting denials (D6, 2026-11-27).

    These may only add evidence or make the verdict stricter, never looser.

    - A denied attempt is attached as ``context``: it settles nothing, so the
      verdict, coverage and gap stay exactly as judged.
    - A successful attempt against a ``must_not_reach`` item is supporting
      evidence that the operation is reachable: the finding fails.
    - A successful attempt on a ``must_still_do`` item is context only.
    """
    if not strikes:
        return f
    added: list[Evidence] = []
    succeeded: list[StrikeObservation] = []
    for o, sha in sorted(strikes, key=lambda x: (x[0].write_key, x[1])):
        e = strike_evidence(o, sha)
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
    unaccepted = unaccepted_inconclusive(
        ((f.target, f.operation) for f in findings if f.verdict == "inconclusive"),
        t.accepted_inconclusive,
    )
    over = inconclusive > t.max_inconclusive or bool(unaccepted)
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
        unaccepted_inconclusive=unaccepted,
    )
