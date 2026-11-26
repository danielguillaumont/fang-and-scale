"""Record mode on hand-written sample logs (not recordings)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.harden.record import RecordError, load_rows, merge, record, still_do_items
from fns.models.contract import load_contract
from fns.yamlio import load_yaml

DATA = Path(__file__).parent / "data" / "sample-logs.json"
LAB_CONTRACT = Path(__file__).resolve().parents[2] / "fixtures" / "lab-run-1" / "contract.fns.yaml"
AGENT = "00000000-0000-4000-8000-000000000006"
runner = CliRunner()


def test_only_successful_rows_by_the_identity_are_recorded() -> None:
    rec = record(load_rows([DATA]), AGENT.upper())
    got = sorted((r.resource, r.operation) for r in rec.resource_ops)
    assert got == [
        ("kv-crown-tiin02", "secrets/get"),
        ("stinvoicestiin02", "blob/read"),
        ("stinvoicestiin02", "blob/write"),
        ("stpayrolltiin02", "listKeys"),
        ("streportstiin02", "blob/read"),
    ]
    assert rec.failed == 2  # the 403 GetBlob and the failed role assignment
    assert rec.other_identity == 1
    assert rec.unmapped == {"StorageBlobLogs:listblobs": 1, "SigninLogs": 1}
    assert [(r.resource, r.operation) for r in rec.directory_ops] == [
        ("tenant", "applications/credentials/update")
    ]


def test_items_use_names_not_arm_ids() -> None:
    items = still_do_items(record(load_rows([DATA]), AGENT))
    assert all("/" not in i["resource"] for i in items)
    assert all(i["source"] == "recorded" for i in items)
    assert items == sorted(items, key=lambda i: i["resource"])


def test_merge_adds_new_items_and_leaves_out_conflicts() -> None:
    m = merge(load_contract(LAB_CONTRACT), record(load_rows([DATA]), AGENT))
    assert m.added == ("streportstiin02 blob/read",)
    assert set(m.already) == {"stinvoicestiin02 blob/read", "stinvoicestiin02 blob/write"}
    assert set(m.conflicts) == {"kv-crown-tiin02 secrets/get", "stpayrolltiin02 listKeys"}
    recorded = [i for i in m.contract.must_still_do if i.source == "recorded"]
    assert [(i.resource, i.operations) for i in recorded] == [("streportstiin02", ("blob/read",))]


def test_bad_input_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(RecordError, match="array"):
        load_rows([bad])
    with pytest.raises(RecordError, match="object"):
        record([1], AGENT)  # type: ignore[list-item]


def test_cli_merges_and_exits_1_on_conflicts(tmp_path: Path) -> None:
    out = tmp_path / "merged.fns.yaml"
    args = ["record", str(DATA), "--identity", AGENT, "--contract", str(LAB_CONTRACT)]
    result = runner.invoke(app, [*args, "--out", str(out)])
    assert result.exit_code == 1, result.output
    assert "CONFLICT stpayrolltiin02 listKeys" in result.output
    assert "added streportstiin02 blob/read" in result.output
    merged = load_contract(out)
    assert any(i.source == "recorded" for i in merged.must_still_do)
    assert load_yaml(out)["contract"] == "billing-agent-blast-radius"


def test_cli_without_contract_prints_items(tmp_path: Path) -> None:
    result = runner.invoke(app, ["record", str(DATA), "--identity", AGENT])
    assert result.exit_code == 0, result.output
    assert '"source": "recorded"' in result.output
    assert "directory applications/credentials/update: seen, not written" in result.output
