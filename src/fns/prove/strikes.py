"""``fns prove --after-strike DIR``: D-1 to D-5 as evidence (D6, approved 2026-11-27).

``DIR`` is a ``fns strike run`` directory: ``plan.json`` and ``strike-run.json``.
Before anything is recorded:

- ``strike-run.json`` must name the same run ID and plan hash as ``plan.json``,
  and that hash must be the plan's own;
- the plan's tenant must be the frozen assertions' tenant, and both runs must be
  the same mode (a FIXTURE strike never becomes LIVE evidence, nor the reverse).

Only after-harden attempts count, and only two outcomes: ``denied`` (a 401 or
403) and ``unexpected-success``. Anything else (a gate denial, an unknown
outcome, another status, not run) says nothing about the boundary and is
dropped. Each one becomes a :class:`~fns.models.assertions.StrikeObservation`
per contract item it observes, journaled after the freeze as a read step.

The verifier decides what they mean, under the guardrail that a strike can never
move a finding toward ``pass``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Final

from fns.journal.sqlite import SqliteJournal
from fns.models.assertions import AssertionSet, StrikeObservation
from fns.probes.runner import FREEZE_STEP, sha256_bytes, write_artifact
from fns.strike.plan import StrikePlan

PLAN_FILE: Final = "plan.json"
RUN_FILE: Final = "strike-run.json"
COUNTED: Final[dict[str, str]] = {"denied": "denied", "unexpected-success": "allowed"}
CONTRACT_ITEM: Final = re.compile(r"^((?:resource|directory|application):[^\s:]+) (\S+)$")
"""``<kind>:<name> <operation>``, as a contract item's target and operation read."""


class AfterStrikeError(ValueError):
    """The strike run cannot be used as evidence for this prove run (nothing recorded)."""


def load_after_strike(directory: Path, aset: AssertionSet) -> list[StrikeObservation]:
    try:
        plan = StrikePlan.model_validate_json((directory / PLAN_FILE).read_bytes())
        run: dict[str, Any] = json.loads((directory / RUN_FILE).read_bytes())
    except (OSError, ValueError) as exc:
        raise AfterStrikeError(f"not a strike run directory: {exc}") from exc
    if run.get("run_id") != plan.run_id:
        raise AfterStrikeError("strike-run.json is for another plan")
    if run.get("plan_hash") != f"sha256:{plan.plan_hash()}":
        raise AfterStrikeError("strike-run.json names another plan hash than plan.json")
    if plan.tenant_id != str(aset.tenant_id).lower():
        raise AfterStrikeError("the strike ran in another tenant than this prove run")
    if run.get("mode") != aset.mode:
        raise AfterStrikeError(f"a {run.get('mode')} strike run cannot be {aset.mode} evidence")
    planned = {w.key: w for w in plan.writes}
    at = plan.created_at  # the strike run records no per-write time; stable on replay
    out: list[StrikeObservation] = []
    for w in run.get("writes", []):
        p = planned.get(str(w.get("key")))
        if p is None:
            raise AfterStrikeError(f"strike-run.json names a write the plan lacks: {w.get('key')}")
        outcome = COUNTED.get(str(w.get("outcome")))
        if p.expect != "denied" or outcome is None:
            continue
        status = w.get("status")
        for item in p.observes:
            m = CONTRACT_ITEM.match(item)
            if m is None:
                continue  # D-1's "first hop" names a path, not a contract item
            target, operation = m[1], m[2]
            out.append(
                StrikeObservation(
                    version=1,
                    mode=aset.mode,
                    strike_run_id=plan.run_id,
                    plan_sha256=plan.plan_hash(),
                    write_key=p.key,
                    strike=p.strike,
                    target=target,
                    operation=operation,
                    outcome=outcome,  # type: ignore[arg-type]
                    http_status=status if isinstance(status, int) else None,
                    observed_at=at,
                )
            )
    return sorted(out, key=lambda o: o.step_key)


def record_strikes(
    journal: SqliteJournal, aset: AssertionSet, observations: list[StrikeObservation], run_dir: Path
) -> None:
    if journal.step_status(aset.run_id, FREEZE_STEP) != "succeeded":
        raise RuntimeError("assertions must be frozen before strike evidence is recorded")
    for obs in observations:

        def body(o: StrikeObservation = obs) -> StrikeObservation:
            write_artifact(run_dir, o.file_bytes())
            return o

        journal.run_step(
            aset.run_id,
            obs.step_key,
            "read",
            f"strike {obs.write_key} {obs.target} {obs.operation}",
            body,
            digest=lambda o: sha256_bytes(o.file_bytes()),
        )
