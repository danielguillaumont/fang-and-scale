"""Generate ``fixtures/strike-demo/`` from the fake tenant (placeholder IDs only).

    uv run python -m tests.strike.make_fixture

``tests/strike/test_replay.py`` fails if the committed files drift from this.
There is no live strike recording yet: the first one comes from the M4 live run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fns.adapters.azure.http import ApiRequest, ApiResponse
from fns.models.base import sha256_hex
from fns.strike.plan import StrikeId
from fns.strike.replay import SCOPE_FILE, Recorder, StrikeRecording, recording_json
from fns.strike.run import run_plan
from fns.strike.strikes import USED_FORMS, build_plan
from fns.strike.transport import StrikeRequest
from fns.yamlio import dumps_yaml
from tests.factories import NOW, SP_AGENT
from tests.scope.writekit import APP_ESC, ESCALATED_FORMS, PRE_ROLES, strike_dict
from tests.strike.faketenant import (
    RECORDED_SCOUT_READS,
    SCOUT,
    FakeTenant,
    FakeWrites,
    Lab,
    MemoryStrikeJournal,
    manifest,
)

RECORDED_FORMS = tuple(op for op in USED_FORMS if op not in ESCALATED_FORMS)
"""The recording holds S1 to S3 and D-1 to D-5 only. S4 needs a token exchange a
recording can't replay without the token, so it is tested against the fake tenant
(tests/strike/test_s4.py), and its scope block is left out here."""
FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "strike-demo"
RUN_IDS = {"before-harden": "202611251200-demo01", "after-harden": "202611251200-demo02"}
STRIKES: dict[str, tuple[StrikeId, ...]] = {
    "before-harden": ("S1", "S2", "S3"),
    "after-harden": ("D-1", "D-2", "D-3", "D-4", "D-5"),
}
DESCRIPTIONS = {
    "before-harden": "Session C, S1 to S3 against the fake lab tenant: every write succeeds "
    "and is undone. Made by tests/strike/make_fixture.py, not recorded live.",
    "after-harden": "Session D, D-1 to D-5 against the fake lab tenant after harden: every "
    "attempt is denied (403). Made by tests/strike/make_fixture.py, not recorded live.",
}


class _Reads:
    def __init__(self, tenant: FakeTenant, rec: Recorder) -> None:
        self.tenant, self.rec = tenant, rec

    def fetch(self, request: ApiRequest) -> ApiResponse:
        return self.rec.read(request, self.tenant.read(request))


class _Writes(FakeWrites):
    def __init__(self, tenant: FakeTenant, rec: Recorder) -> None:
        super().__init__(tenant)
        self.rec = rec

    def _exchange(self, request: StrikeRequest) -> tuple[int, object, str | None]:
        status, body, rid = super()._exchange(request)
        self.rec.write(request, status, body, rid)
        return status, body, rid


def scope_text(lab: Lab) -> str:
    data: dict[str, Any] = json.loads(lab.m.canonical_json())
    return (
        "# FIXTURE scope for fns strike --fixture (placeholder IDs; never a real tenant)\n"
        + dumps_yaml(data)
    )


def make(scenario: str) -> tuple[str, StrikeRecording]:
    lab = Lab(
        m=manifest(
            ops=RECORDED_FORMS, scout=RECORDED_SCOUT_READS, strike=strike_dict(escalation=None)
        )
    )
    lab.tenant.roles[APP_ESC] = PRE_ROLES  # recorded before Terraform defined the marker
    lab.tenant.hardened = scenario == "after-harden"
    rec = Recorder()
    reads = _Reads(lab.tenant, rec)
    lab.reads = reads  # type: ignore[assignment]
    scope = scope_text(lab)
    plan = build_plan(
        STRIKES[scenario],
        lab.m,
        sha256_hex(scope),
        lab.reader(),
        NOW,
        run_id=RUN_IDS[scenario],
    )
    rec.phase = "run"
    run = run_plan(
        plan,
        plan.plan_hash(),
        gate_factory=lab.gate_factory,
        signed_in_principal=SP_AGENT,
        scope_sha256=sha256_hex(scope),
        transport=_Writes(lab.tenant, rec),
        reader=lab.reader(),
        journal=MemoryStrikeJournal(),
        mode="FIXTURE",
        clock=lab.clock,
    )
    assert run.verified and int(run.exit_code) == 0, run.to_dict()
    return scope, rec.recording(
        description=DESCRIPTIONS[scenario],
        now=NOW,
        run_id=RUN_IDS[scenario],
        strikes=STRIKES[scenario],
        agent=SP_AGENT,
        scout=SCOUT,
    )


def files() -> dict[str, str]:
    out: dict[str, str] = {}
    for scenario in STRIKES:
        scope, recording = make(scenario)
        out[SCOPE_FILE] = scope
        out[f"{scenario}.json"] = recording_json(recording)
    return out


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in files().items():
        (FIXTURE_DIR / name).write_bytes(text.encode())
        sys.stdout.write(f"wrote {name}\n")


if __name__ == "__main__":
    main()
