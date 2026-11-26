from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from typer.testing import CliRunner

from fns.cli import app
from fns.models.scope import load_scope
from tests.factories import NOW, TENANT, scope_dict

ROOT = Path(__file__).resolve().parents[2]
runner = CliRunner()


def _write(tmp_path: Path, data: dict[str, Any], extra: str = "") -> Path:
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data, sort_keys=False) + extra, encoding="utf-8")
    return p


def _fresh(**overrides: Any) -> dict[str, Any]:
    # The CLI reads the real clock, so expiry is relative to now (no time bombs).
    expires = (datetime.now(UTC) + timedelta(days=3)).isoformat()
    return scope_dict(expires_at=expires, **overrides)


def test_example_scope_is_valid() -> None:
    m = load_scope(ROOT / "scope.example.yaml", now=NOW)
    assert m.allowed_operations["scout"]


def test_valid_scope_summary(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scope", "check", str(_write(tmp_path, _fresh()))])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "valid" in out
    assert TENANT in out
    assert "arm:Microsoft.Authorization/roleAssignments/read" in out
    assert "2d" in out  # time remaining


def test_empty_operations_warn_everything_denied(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scope", "check", str(_write(tmp_path, _fresh(allowed_operations={})))]
    )
    assert result.exit_code == 0
    assert "every call will be denied" in result.output


def test_invalid_scope_exits_2_with_location(tmp_path: Path) -> None:
    bad = _fresh(allowed_resource_groups=["rg-fns-lab"])
    result = runner.invoke(app, ["scope", "check", str(_write(tmp_path, bad))])
    assert result.exit_code == 2
    assert "allowed_resource_groups" in result.output


def test_write_under_scout_rejected(tmp_path: Path) -> None:
    bad = _fresh(
        allowed_operations={"scout": ["arm:Microsoft.Authorization/roleAssignments/write"]}
    )
    result = runner.invoke(app, ["scope", "check", str(_write(tmp_path, bad))])
    assert result.exit_code == 2
    assert "read-only" in result.output


def test_expired_scope_exits_2(tmp_path: Path) -> None:
    old = scope_dict(expires_at="2020-01-01T00:00:00Z")
    result = runner.invoke(app, ["scope", "check", str(_write(tmp_path, old))])
    assert result.exit_code == 2
    assert "expired" in result.output


def test_duplicate_key_exits_2(tmp_path: Path) -> None:
    path = _write(tmp_path, _fresh(), extra="tenant_id: 00000000-0000-4000-8000-000000000002\n")
    result = runner.invoke(app, ["scope", "check", str(path)])
    assert result.exit_code == 2
    assert "duplicate key" in result.output


def test_missing_file_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scope", "check", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 2
    assert "not found" in result.output


def test_markup_in_values_is_not_interpreted(tmp_path: Path) -> None:
    data = _fresh(
        test_identities=[
            {
                "object_id": "00000000-0000-4000-8000-000000000100",
                "kind": "servicePrincipal",
                "name": "[bold red]x[/]",
            }
        ]
    )
    result = runner.invoke(app, ["scope", "check", str(_write(tmp_path, data))])
    assert result.exit_code == 0
    assert "[bold red]x[/]" in result.output
