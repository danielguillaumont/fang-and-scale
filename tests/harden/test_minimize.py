"""The minimizer and the Terraform lever map, on the lab-run-1 fixture and lab/*.tf."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.contain.evaluate import evaluate
from fns.contain_run import demo_contract, run_demo_contain
from fns.harden.minimize import NoProposalError, edited_files, minimize, render_diff
from fns.harden.tfmap import TfParseError, _pattern, apply_to_snapshot, map_lab, parse_blocks
from fns.models.contract import Contract
from fns.models.snapshot import HasAppRole, HasRbacRole, Snapshot

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "lab"
LAB_RUN = ROOT / "fixtures" / "lab-run-1"
runner = CliRunner()


@pytest.fixture(scope="module")
def snapshot(tmp_path_factory: pytest.TempPathFactory) -> Snapshot:
    scout, _ = run_demo_contain(tmp_path_factory.mktemp("scout"), LAB_RUN)
    return scout.snapshot


def test_lab_levers_and_unmapped_reasons(snapshot: Snapshot) -> None:
    m = map_lab(LAB, snapshot)
    kinds = {(lv.address, lv.kind) for lv in m.levers}
    assert ("azurerm_role_assignment.billing_agent_rg_contributor", "rbac") in kinds
    assert ("azuread_app_role_assignment.billing_agent_owned_by", "app-role") in kinds
    assert ("azuread_application.escalation_target", "owner") in kinds
    assert ("azurerm_storage_account.payroll", "shared-key") in kinds
    reasons = {u.address: u.reason for u in m.unmapped}
    assert "operator" in reasons["azurerm_role_assignment.runner_kv_secrets"]
    assert "for_each" in reasons["azuread_app_role_assignment.scout_graph"]


def test_interpolation_never_crosses_a_path_segment() -> None:
    p = _pattern("/subscriptions/${var.subscription_id}")
    assert p.match("/subscriptions/abc")
    assert not p.match("/subscriptions/abc/resourcegroups/rg")


def test_parser_respects_strings_and_refuses_open_blocks(tmp_path: Path) -> None:
    tf = tmp_path / "x.tf"
    tf.write_text('resource "a" "b" {\n  name = "{not a brace"\n}\n', encoding="utf-8")
    (block,) = parse_blocks(tf)
    assert (block.start, block.end, block.attrs["name"]) == (0, 2, '"{not a brace"')
    tf.write_text('resource "a" "b" {\n  name = "x"\n', encoding="utf-8")
    with pytest.raises(TfParseError, match="never closes"):
        parse_blocks(tf)


def test_snapshot_side_of_a_lever_removes_only_its_edge(snapshot: Snapshot) -> None:
    m = map_lab(LAB, snapshot)
    (contributor,) = [lv for lv in m.levers if lv.address.endswith("billing_agent_rg_contributor")]
    (owned_by,) = [lv for lv in m.levers if lv.address.endswith("billing_agent_owned_by")]
    after = apply_to_snapshot(snapshot, (contributor, owned_by))
    assert len(snapshot.edges) - len(after.edges) == 2
    assert not any(
        isinstance(e, HasAppRole)
        and e.src == owned_by.principal
        and e.app_role_value == "Application.ReadWrite.OwnedBy"
        for e in after.edges
    )
    assert (
        sum(isinstance(e, HasRbacRole) and e.src == contributor.principal for e in after.edges) == 1
    )


def test_lab_proposal_is_minimal_keeps_legitimate_use_and_is_deterministic(
    snapshot: Snapshot,
) -> None:
    contract = demo_contract(LAB_RUN)
    p = minimize(contract, snapshot, LAB)
    assert [lv.address for lv in p.levers] == [
        "azuread_app_role_assignment.billing_agent_owned_by",
        "azurerm_role_assignment.billing_agent_rg_contributor",
    ]
    assert (p.before.critical, p.after.critical) == (6, 0)
    assert p.after.still_do_allowed == p.before.still_do_allowed
    assert p.alternatives  # removing the ownership instead also works
    # No single lever is enough: the search really is minimal.
    for lever in p.candidates:
        ev = evaluate(contract, apply_to_snapshot(snapshot, (lever,)))
        assert ev.summary.critical > 0
    assert minimize(contract, snapshot, LAB).plan_hash == p.plan_hash


def test_edited_lab_still_parses_without_the_removed_blocks(
    snapshot: Snapshot, tmp_path: Path
) -> None:
    m = map_lab(LAB, snapshot)
    p = minimize(demo_contract(LAB_RUN), snapshot, LAB, lab=m)
    files = edited_files(LAB, m, p.levers)
    assert set(files) == {lv.file for lv in p.levers}
    for name, (_, new) in files.items():
        out = tmp_path / name
        out.write_text("\n".join(new) + "\n", encoding="utf-8")
        addresses = {b.address for b in parse_blocks(out)}
        before = {b.address for b in parse_blocks(LAB / name)}
        removed = {lv.address for lv in p.levers if lv.file == name}
        assert addresses == before - removed
    assert render_diff(LAB, m, ()) == ""


def test_owner_and_shared_key_edits(snapshot: Snapshot) -> None:
    m = map_lab(LAB, snapshot)
    owner = next(lv for lv in m.levers if lv.kind == "owner")
    key = next(lv for lv in m.levers if lv.kind == "shared-key")
    diff = render_diff(LAB, m, (owner, key))
    assert "+  owners       = local.owners" in diff
    assert re.search(r"^\+  shared_access_key_enabled += false$", diff, re.M)
    assert re.search(r"^-  shared_access_key_enabled += true$", diff, re.M)


def test_already_satisfied_contract_needs_no_change(snapshot: Snapshot) -> None:
    contract = Contract.model_validate(
        {
            "version": 1,
            "contract": "nothing-to-do",
            "assume_compromised": "sp:sp-fns-scout",
            "must_not_reach": [{"resource": "kv-crown-tiin02", "operations": ["secrets/get"]}],
        }
    )
    p = minimize(contract, snapshot, LAB)
    assert p.levers == () and p.diff == ""


def test_removal_only_cannot_split_one_role(snapshot: Snapshot) -> None:
    """H1: read must stay, write must go, one role grants both: no removal-only fix."""
    contract = Contract.model_validate(
        {
            "version": 1,
            "contract": "split",
            "assume_compromised": "sp:sp-billing-agent",
            "must_not_reach": [{"resource": "stinvoicestiin02", "operations": ["blob/write"]}],
            "must_still_do": [{"resource": "stinvoicestiin02", "operations": ["blob/read"]}],
        }
    )
    with pytest.raises(NoProposalError, match="no combination"):
        minimize(contract, snapshot, LAB)


def test_cli_harden(snapshot: Snapshot, tmp_path: Path) -> None:
    snap = tmp_path / "s.json"
    snap.write_text(snapshot.canonical_json(), encoding="utf-8")
    patch = tmp_path / "h.patch"
    base = ["harden", "--contract", str(LAB_RUN / "contract.fns.yaml"), "--snapshot", str(snap)]
    result = runner.invoke(app, [*base, "--out", str(patch)])
    assert result.exit_code == 0, result.output
    assert all(line.startswith("FIXTURE ") for line in result.output.splitlines() if line.strip())
    assert "plan sha256:" in result.output and "not applied" in result.output
    assert patch.read_text(encoding="utf-8").startswith("--- a/lab/")
    refused = runner.invoke(app, [*base, "--apply"])
    assert refused.exit_code == 2
