"""Defence mutation testing on the lab-run-1 fixture, lab/*.tf and the bundled demo."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.contain_run import demo_contract, run_demo_contain
from fns.harden.tfmap import apply_to_snapshot, map_lab
from fns.models.contract import Contract
from fns.models.mutation import MutationReport
from fns.models.snapshot import Snapshot
from fns.mutate import MutateError, apply_mutant, mutate, prepare
from fns.mutate_cli import exit_code

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "lab"
LAB_RUN = ROOT / "fixtures" / "lab-run-1"
GOLDEN = ROOT / "tests" / "golden" / "lab-run-1-mutate.digest"
NOW = datetime(2026, 11, 26, tzinfo=UTC)
runner = CliRunner()


@pytest.fixture(scope="module")
def lab_snapshot(tmp_path_factory: pytest.TempPathFactory) -> Snapshot:
    scout, _ = run_demo_contain(tmp_path_factory.mktemp("lab"), LAB_RUN)
    return scout.snapshot


@pytest.fixture(scope="module")
def demo_snapshot(tmp_path_factory: pytest.TempPathFactory) -> Snapshot:
    scout, _ = run_demo_contain(tmp_path_factory.mktemp("demo"))
    return scout.snapshot


def _run(contract: Contract, snap: Snapshot, lab: Path | None, harden: bool) -> MutationReport:
    return mutate(contract, snap, lab, harden=harden, generated_at=NOW, tool_version="test")


def test_hardened_lab_kills_what_the_contract_forbids(lab_snapshot: Snapshot) -> None:
    r = _run(demo_contract(LAB_RUN), lab_snapshot, LAB, True)
    assert r.baseline_failures == 0
    assert r.hardened_with == (
        "azuread_app_role_assignment.billing_agent_owned_by",
        "azurerm_role_assignment.billing_agent_rg_contributor",
    )
    outcome = {m.id: m.outcome for m in r.mutants}
    assert outcome == {
        "owner-at-rg:rg-fns-lab": "killed",
        "listkeys:stinvoicestiin02": "survived",
        "listkeys:stpayrolltiin02": "killed",
        "graph-app-permission:AppRoleAssignment.ReadWrite.All": "killed",
        "graph-app-permission:Application.ReadWrite.All": "killed",
        "graph-app-permission:RoleManagement.ReadWrite.Directory": "killed",
        "app-owner:id-verifier": "survived",
        "app-owner:sp-fns-scout": "survived",
    }
    assert r.score == "5/8"
    assert all(m.rung == "modeled" for m in r.mutants)
    assert all(m.terraform_diff and m.terraform_diff.startswith("--- a/lab/") for m in r.mutants)
    assert [n.operator for n in r.not_applicable] == ["remove-deny-assignment"]
    assert exit_code(r, 0) == 1
    assert exit_code(r, 3) == 0


def test_unhardened_baseline_cannot_score(lab_snapshot: Snapshot) -> None:
    r = _run(demo_contract(LAB_RUN), lab_snapshot, LAB, False)
    assert r.baseline_failures == 6
    assert r.killed == 0
    assert exit_code(r, 99) == 1


def test_terraform_mutants_round_trip_through_the_lever_map(
    lab_snapshot: Snapshot, tmp_path: Path
) -> None:
    """Each mutant's Terraform maps back to a lever that removes exactly its edge."""
    prep = prepare(demo_contract(LAB_RUN), lab_snapshot, LAB, harden=True)
    base_edges = {e.canonical_json() for e in prep.baseline.edges}
    checked = 0
    for m in prep.mutants:
        if m.terraform_lines is None or m.terraform_file is None:
            continue
        lab = tmp_path / m.id.replace(":", "_").replace(".", "_")
        lab.mkdir()
        for name, lines in prep.files.items():
            text = m.terraform_lines if name == m.terraform_file else lines
            (lab / name).write_text("\n".join(text) + "\n", encoding="utf-8")
        mutated = apply_mutant(prep.baseline, m)
        added = {e.canonical_json() for e in mutated.edges} - base_edges
        assert len(added) == 1, m.id
        levers = [
            lv
            for lv in map_lab(lab, mutated).levers
            if apply_to_snapshot(mutated, (lv,)).edges != mutated.edges
            and {e.canonical_json() for e in apply_to_snapshot(mutated, (lv,)).edges} == base_edges
        ]
        assert levers, f"{m.id}: no lever undoes the mutant"
        checked += 1
    assert checked == 8


def test_bundled_demo_removes_its_deny_assignment(demo_snapshot: Snapshot) -> None:
    r = _run(demo_contract(None), demo_snapshot, None, False)
    deny = [m for m in r.mutants if m.operator == "remove-deny-assignment"]
    assert len(deny) == 1
    assert deny[0].terraform_diff is None
    assert "created by Azure" in (deny[0].terraform_note or "")
    assert all(m.terraform_note == "no lab Terraform" or m.terraform_note for m in r.mutants)
    assert r.baseline_failures > 0  # the bundled demo is not hardened


def test_harden_needs_terraform_and_identity_must_resolve(demo_snapshot: Snapshot) -> None:
    with pytest.raises(MutateError, match="needs the lab"):
        _run(demo_contract(None), demo_snapshot, None, True)
    ghost = demo_contract(None).model_copy(update={"assume_compromised": "sp:nobody"})
    with pytest.raises(MutateError, match="cannot mutate"):
        _run(ghost, demo_snapshot, None, False)


def test_report_is_deterministic_and_matches_golden(lab_snapshot: Snapshot) -> None:
    a = _run(demo_contract(LAB_RUN), lab_snapshot, LAB, True)
    b = mutate(
        demo_contract(LAB_RUN),
        lab_snapshot,
        LAB,
        harden=True,
        generated_at=datetime(2030, 1, 1, tzinfo=UTC),
        tool_version="other",
    )
    assert a.digest() == b.digest()
    assert a.digest() == GOLDEN.read_text(encoding="utf-8").strip()


def test_cli_demo_and_file_mode(lab_snapshot: Snapshot, tmp_path: Path) -> None:
    out = tmp_path / "m.json"
    result = runner.invoke(
        app,
        [
            "demo",
            "mutate",
            "--fixture",
            str(LAB_RUN),
            "--lab",
            str(LAB),
            "--out",
            str(tmp_path / "fns"),
            "--json",
            str(out),
        ],
    )
    assert result.exit_code == 1, result.output
    assert all(line.startswith("FIXTURE ") for line in result.output.splitlines() if line.strip())
    assert "Mutation score 5/8" in result.output
    report = MutationReport.model_validate(json.loads(out.read_text(encoding="utf-8")))
    assert report.score == "5/8"

    snap = tmp_path / "s.json"
    snap.write_text(lab_snapshot.canonical_json(), encoding="utf-8")
    base = ["mutate", "--contract", str(LAB_RUN / "contract.fns.yaml"), "--snapshot", str(snap)]
    ok = runner.invoke(app, [*base, "--lab", str(LAB), "--harden", "--max-survivors", "3"])
    assert ok.exit_code == 0, ok.output
    assert "within the allowed 3" in ok.output
    diffed = runner.invoke(app, [*base, "--lab", str(LAB), "--harden", "--diff"])
    assert "+  owners       = concat(local.owners" in diffed.output
    bad = runner.invoke(app, [*base, "--harden"])
    assert bad.exit_code == 2  # invalid input: --harden without --lab


def test_demo_needs_a_checkout(tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", "mutate", "--fixture", str(tmp_path / "missing")])
    assert result.exit_code == 2
    assert "repository checkout" in result.output
