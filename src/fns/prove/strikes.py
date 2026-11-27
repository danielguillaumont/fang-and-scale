"""``fns prove --after-strike DIR``: D-1 to D-5 as evidence (D6, approved 2026-11-27).

``DIR`` is a ``fns strike run`` directory: ``plan.json`` and ``strike-run.json``.
Before anything is recorded:

- ``strike-run.json`` must name the same run ID and plan hash as ``plan.json``,
  and that hash must be the plan's own;
- the plan's tenant must be the frozen assertions' tenant, and both runs must be
  the same mode (a FIXTURE strike never becomes LIVE evidence, nor the reverse).

Only after-harden attempts (D-1 to D-5, planned ``expect: denied``) count, and
only two outcomes: ``denied`` (a 401 or 403) and ``unexpected-success``. A
before-harden strike never counts, whatever its plan says: S4's token claims, in
particular, are a safety stop and never evidence (approved 2026-11-27). Anything
else (a gate denial, an unknown outcome, another status, not run) says nothing
about the boundary and is dropped. Each one becomes a
:class:`~fns.models.assertions.StrikeObservation` per contract item it observes,
journaled after the freeze as a read step.

The verifier decides what they mean (``fns.verify.verdict``): a LIVE 403 on the
item's exact operation and object counts like an observed probe denial (option B,
approved 2026-11-27); every other result is context or fails the finding. Each
observation carries the planned write's operation and object ID for that check.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from fns.inputcap import MAX_RECORD_BYTES, read_capped
from fns.journal.sqlite import SqliteJournal
from fns.models.assertions import AssertionSet, StrikeObservation
from fns.models.strike_record import StrikeRunRecord
from fns.probes.runner import FREEZE_STEP, sha256_bytes, write_artifact
from fns.strike.plan import AFTER_HARDEN, StrikePlan

PLAN_FILE: Final = "plan.json"
RUN_FILE: Final = "strike-run.json"
COUNTED: Final[dict[str, str]] = {"denied": "denied", "unexpected-success": "allowed"}
CONTRACT_ITEM: Final = re.compile(r"^((?:resource|directory|application):[^\s:]+) (\S+)$")
"""``<kind>:<name> <operation>``, as a contract item's target and operation read."""
_OBJECT_IN_URL: Final = re.compile(
    r"/(?:applications|servicePrincipals)/([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})/"
)
"""The directory object a Graph write names. The verifier compares it with the
frozen target's object ID (option B); prove only copies it."""


class AfterStrikeError(ValueError):
    """The strike run cannot be used as evidence for this prove run (nothing recorded)."""


def load_after_strike(directory: Path, aset: AssertionSet) -> list[StrikeObservation]:
    try:
        plan = StrikePlan.model_validate_json(read_capped(directory / PLAN_FILE, MAX_RECORD_BYTES))
        run = StrikeRunRecord.model_validate_json(
            read_capped(directory / RUN_FILE, MAX_RECORD_BYTES)
        )
    except (OSError, ValueError) as exc:
        raise AfterStrikeError(f"not a strike run directory: {exc}") from exc
    if run.run_id != plan.run_id:
        raise AfterStrikeError("strike-run.json is for another plan")
    if run.plan_hash != f"sha256:{plan.plan_hash()}":
        raise AfterStrikeError("strike-run.json names another plan hash than plan.json")
    if plan.tenant_id != str(aset.tenant_id).lower():
        raise AfterStrikeError("the strike ran in another tenant than this prove run")
    if run.mode != aset.mode:
        raise AfterStrikeError(f"a {run.mode} strike run cannot be {aset.mode} evidence")
    planned = {w.key: w for w in plan.writes}
    at = plan.created_at  # the strike run records no per-write time; stable on replay
    out: list[StrikeObservation] = []
    for w in run.writes:
        p = planned.get(w.key)
        if p is None:
            raise AfterStrikeError(f"strike-run.json names a write the plan lacks: {w.key}")
        outcome = COUNTED.get(w.outcome)
        if p.strike not in AFTER_HARDEN or p.expect != "denied" or outcome is None:
            continue
        status = w.status
        object_id = _OBJECT_IN_URL.search(p.request.url)
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
                    http_status=status,
                    observed_at=at,
                    request_operation=p.request.operation,
                    request_object_id=object_id[1].lower() if object_id else None,
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
