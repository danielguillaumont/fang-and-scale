from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from fns import schema as schema_mod
from fns.cli import app
from fns.models.snapshot import Snapshot
from fns.yamlio import load_yaml
from tests.factories import scope_dict, snapshot_dict

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
runner = CliRunner()


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / schema_mod.filename(name)).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


@pytest.mark.parametrize("name", sorted(schema_mod.SCHEMAS))
def test_committed_schema_matches_models(name: str) -> None:
    committed = (SCHEMAS / schema_mod.filename(name)).read_bytes()
    assert committed == schema_mod.render(name).encode("utf-8"), "run `uv run poe schema`"
    assert b"\r\n" not in committed


@pytest.mark.parametrize("name", sorted(schema_mod.SCHEMAS))
def test_schema_is_valid_draft_2020_12(name: str) -> None:
    schema = schema_mod.schema_for(name)
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"].endswith("2020-12/schema")


def test_example_contract_validates_against_schema() -> None:
    for path in sorted((ROOT / "contracts" / "examples").glob("*.fns.yaml")):
        _validator("contract").validate(load_yaml(path))


def test_scope_sample_validates_against_schema() -> None:
    _validator("scope").validate(scope_dict())


def test_snapshot_sample_validates_against_schema() -> None:
    data = json.loads(Snapshot.model_validate(snapshot_dict()).canonical_json())
    _validator("snapshot").validate(data)


def test_schema_rejects_old_directory_shorthand() -> None:
    bad = load_yaml(ROOT / "contracts" / "examples" / "billing-agent.fns.yaml")
    bad["must_not_reach"] = [{"directory": ["roleAssignments/write"]}]
    assert list(_validator("contract").iter_errors(bad))


def test_cli_schema_writes_lf_files(tmp_path: Path) -> None:
    result = runner.invoke(app, ["schema", "--out", str(tmp_path)])
    assert result.exit_code == 0, result.output
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == [
        "assertions.schema.json",
        "contain-report.schema.json",
        "contract.schema.json",
        "evidence-bundle.schema.json",
        "mutation-report.schema.json",
        "scope.schema.json",
        "snapshot.schema.json",
    ]
    for p in tmp_path.iterdir():
        assert b"\r\n" not in p.read_bytes()


def test_cli_schema_check_passes_on_repo() -> None:
    result = runner.invoke(app, ["schema", "--check", "--out", str(SCHEMAS)])
    assert result.exit_code == 0, result.output


def test_cli_schema_check_detects_drift(tmp_path: Path) -> None:
    runner.invoke(app, ["schema", "--out", str(tmp_path)])
    target = tmp_path / "scope.schema.json"
    target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8", newline="\n")
    (tmp_path / "contract.schema.json").unlink()
    result = runner.invoke(app, ["schema", "--check", "--out", str(tmp_path)])
    assert result.exit_code == 1
    assert "scope.schema.json" in result.output
    assert "contract.schema.json" in result.output
