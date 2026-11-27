"""The journal fsyncs every commit in the product; only the test session lowers it."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from fns.journal import sqlite as journal_sqlite
from fns.journal.sqlite import SqliteJournal

SOURCE = Path(journal_sqlite.__file__).read_text(encoding="utf-8")


def test_the_product_value_is_full() -> None:
    tree = ast.parse(SOURCE)
    values = [
        node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "SYNCHRONOUS"
        and isinstance(node.value, ast.Constant)
    ]
    assert values == ["FULL"]
    assert 'f"PRAGMA synchronous = {SYNCHRONOUS}"' in SOURCE


def test_a_journal_opened_with_the_product_value_is_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(journal_sqlite, "SYNCHRONOUS", "FULL")
    with SqliteJournal(tmp_path / "j.sqlite") as j:
        (level,) = j._conn.execute("PRAGMA synchronous").fetchone()
    assert level == 2  # FULL


def test_nothing_but_the_test_session_changes_it() -> None:
    src = Path(journal_sqlite.__file__).resolve().parents[1]
    users = sorted(
        p.relative_to(src).as_posix()
        for p in src.rglob("*.py")
        if "SYNCHRONOUS" in p.read_text(encoding="utf-8")
    )
    assert users == ["journal/sqlite.py"]
