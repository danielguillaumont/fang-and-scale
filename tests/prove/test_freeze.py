"""Freezing: what each path can be refuted by, and that freezing is deterministic."""

from __future__ import annotations

from pathlib import Path

import pytest

from fns.models.assertions import Assertion, AssertionSet
from fns.prove.freeze import freeze
from tests.prove.helpers import lab, prepared


def _one(aset: AssertionSet, target: str, op: str) -> Assertion:
    (a,) = [a for a in aset.assertions if a.target.endswith(target) and a.operation == op]
    return a


def _probe(a: Assertion, pid: str) -> tuple[str, str, str]:
    (p,) = [p for p in a.probes if p.id == pid]
    return p.kind, p.purpose, p.action


def test_indirect_way_is_refuted_only_by_its_own_action(tmp_path: Path) -> None:
    lb = lab(tmp_path)
    aset = freeze(lb.contract, lb.snapshot, lb.report, frozen_at=lb.snapshot.collected_at)
    a = _one(aset, "kv-crown-tiin02", "secrets/get")
    (path,) = a.paths
    assert path.summary == "assume-compromised -> kv-control-to-data"
    (ref,) = path.refuted_by
    assert _probe(a, ref) == ("arm-permissions", "hop", "Microsoft.KeyVault/vaults/write")
    # The direct read is probed, but a denial of it never refutes this path.
    assert any(p.kind == "data-read" and p.purpose == "direct" for p in a.probes)


def test_escalation_paths_cannot_be_refuted(tmp_path: Path) -> None:
    lb = lab(tmp_path)
    aset = freeze(lb.contract, lb.snapshot, lb.report, frozen_at=lb.snapshot.collected_at)
    a = _one(aset, "tenant", "roleAssignments/write")
    assert a.paths
    assert all(p.refuted_by == () for p in a.paths)
    assert a.probes == ()


def test_direct_grant_is_refuted_by_its_check_or_a_denied_read(tmp_path: Path) -> None:
    lb = lab(tmp_path)
    aset = freeze(lb.contract, lb.snapshot, lb.report, frozen_at=lb.snapshot.collected_at)
    a = _one(aset, "stinvoicestiin02", "blob/read")
    (direct,) = [p for p in a.paths if p.summary.endswith("rbac-data-action")]
    kinds = sorted(_probe(a, r)[0] for r in direct.refuted_by)
    assert kinds == ["arm-permissions", "data-read"]


def test_open_surfaces_and_thresholds_are_frozen(tmp_path: Path) -> None:
    lb = lab(tmp_path)
    aset = freeze(lb.contract, lb.snapshot, lb.report, frozen_at=lb.snapshot.collected_at)
    assert all("pim-eligibility" in a.open_surfaces for a in aset.assertions)
    assert aset.thresholds.max_critical_reachable == lb.contract.budget.max_critical_reachable
    assert aset.report_digest == lb.report.digest()


def test_freezing_is_deterministic_and_bound_to_its_inputs(tmp_path: Path) -> None:
    a1, *_ = prepared(tmp_path / "a")
    a2, *_ = prepared(tmp_path / "b")
    assert a1.file_bytes() == a2.file_bytes()
    lb = lab(tmp_path / "c")
    other = lb.contract.model_copy(update={"on_inconclusive": "warn"})
    with pytest.raises(ValueError, match="contract"):
        freeze(other, lb.snapshot, lb.report, frozen_at=lb.snapshot.collected_at)


def test_fixture_probes_make_the_run_fixture_evidence(tmp_path: Path) -> None:
    aset, run_dir, probes, _ = prepared(tmp_path)
    assert aset.mode == "FIXTURE"
    assert (run_dir / "assertions.json").read_bytes() == aset.file_bytes()
    assert probes.failed == ()
    assert len(probes.observations) == sum(len(a.probes) for a in aset.assertions)
