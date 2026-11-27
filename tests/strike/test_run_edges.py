"""Strike-engine safety branches no test reached (coverage, queue item 10).

Each test names the property it holds:
- no lab tags, no plan;
- an unreadable lab, no start;
- the wrong identity, no cleanup;
- an undo that cannot be resolved is recorded and fails verification;
- a read-back that fails or looks wrong is never counted as "restored".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fns.adapters.azure.http import ApiRequest, ApiResponse, TransportError
from fns.exitcodes import ExitCode
from fns.journal.sqlite import SqliteJournal
from fns.strike.plan import PlanError
from fns.strike.run import StrikeStartError, cleanup
from fns.strike.strikes import build_plan
from tests.factories import NOW
from tests.scope.writekit import APP_ESC
from tests.strike.faketenant import SCOPE_SHA, FakeWrites, Lab
from tests.strike.test_run import RUN, clean, go, plan_for, restored


@pytest.fixture
def jpath(tmp_path: Path) -> Path:
    return tmp_path / "journal.sqlite"


def _reads_fail(lab: Lab, *, once_written: bool) -> None:
    """Every scout read raises: always, or once the run has sent its first write."""
    assert lab.reads is not None
    original = lab.reads.fetch

    def fetch(request: ApiRequest) -> ApiResponse:
        if not once_written or lab.tenant.sent:
            raise TransportError("connection reset")
        return original(request)

    lab.reads.fetch = fetch  # type: ignore[method-assign]


# --- planning: lab tags -------------------------------------------------------------


@pytest.mark.parametrize(
    ("strike", "change", "match"),
    [
        ("S1", {"storage_tags": {}}, "payroll storage account lacks the lab tags"),
        (
            "S1",
            {"storage_tags": {"project": "fang-and-scale", "purpose": "prod"}},
            "lacks the lab tags",
        ),
        ("S2", {"vault_tags": {"project": "fang-and-scale"}}, "Key Vault lacks the lab tags"),
        ("S1", {"key_times": {"key1": "2026-11-01T00:00:00Z"}}, "no keyCreationTime"),
    ],
)
def test_no_plan_for_an_arm_target_that_is_not_visibly_a_lab_resource(
    strike: str, change: dict[str, Any], match: str
) -> None:
    lab = Lab()
    for attr, value in change.items():
        setattr(lab.tenant, attr, value)
    with pytest.raises(PlanError, match=match):
        build_plan((strike,), lab.m, SCOPE_SHA, lab.reader(), NOW, run_id=RUN)  # type: ignore[arg-type]
    assert lab.tenant.sent == []


# --- starting and cleaning up --------------------------------------------------------


def test_a_lab_that_cannot_be_reread_is_never_written(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    _reads_fail(lab, once_written=False)
    with SqliteJournal(jpath) as j, pytest.raises(StrikeStartError, match="re-read the pre-state"):
        go(lab, plan, j)
    assert lab.tenant.sent == []


def test_cleanup_as_another_identity_is_refused_before_anything_is_sent(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    with SqliteJournal(jpath) as j:
        go(lab, plan, j)
        sent = len(lab.tenant.sent)
        with pytest.raises(StrikeStartError, match="another identity"):
            cleanup(
                plan,
                plan.plan_hash(),
                gate_factory=lab.gate_factory,
                signed_in_principal=APP_ESC,
                transport=FakeWrites(lab.tenant),
                reader=lab.reader(),
                journal=j,
            )
    assert len(lab.tenant.sent) == sent


# --- verification never assumes ------------------------------------------------------


def test_a_read_back_that_fails_is_not_restored(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab)
    before = lab.tenant.snapshot()
    _reads_fail(lab, once_written=True)
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j)
    assert restored(lab, before, s1=True)  # the undos were still sent
    assert run.checks and not any(c.ok for c in run.checks)
    assert all("could not read it back" in c.detail for c in run.checks)
    assert run.exit_code == ExitCode.EVIDENCE_INVALID


def test_an_undo_that_cannot_be_resolved_is_recorded_then_cleanup_finishes_it(jpath: Path) -> None:
    """addPassword's answer is lost and the scout cannot read: the undo is unknown."""
    lab = Lab()
    plan = plan_for(lab, ("S3",))
    before = lab.tenant.snapshot()
    _reads_fail(lab, once_written=True)
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j, FakeWrites(lab.tenant, ["raise-after"]))
        assert run.writes[0].outcome == "unknown"
        assert run.writes[0].undo == ["unresolved"]
        assert run.exit_code == ExitCode.EVIDENCE_INVALID
        events = [(k, p) for k, p, _ in j.strike_events(plan.run_id)]
        assert (plan.writes[0].key, "undo-error") in events
        assert lab.tenant.snapshot() != before  # the credential is still there, and the run says so

        assert lab.reads is not None
        lab.reads.fetch = lambda request: lab.tenant.read(request)  # type: ignore[method-assign]
        after = clean(lab, plan, j)
    assert lab.tenant.snapshot() == before
    assert after.exit_code == ExitCode.OK


def test_a_key_time_that_is_not_a_time_is_not_a_regeneration(jpath: Path) -> None:
    lab = Lab()
    plan = plan_for(lab, ("S1",))
    original = lab.tenant.read

    def read(request: ApiRequest) -> ApiResponse:
        resp = original(request)
        if lab.tenant.sent and "storageAccounts" in request.url:
            body = dict(resp.body)
            body["properties"] = {"keyCreationTime": {"key1": "garbage", "key2": "garbage"}}
            return ApiResponse(resp.status, body)
        return resp

    lab.tenant.read = read  # type: ignore[method-assign]
    with SqliteJournal(jpath) as j:
        run = go(lab, plan, j)
    (keys,) = [c for c in run.checks if c.what.startswith("keys ")]
    assert keys.ok is False and "key1" in keys.detail and "key2" in keys.detail
    assert run.exit_code == ExitCode.EVIDENCE_INVALID
