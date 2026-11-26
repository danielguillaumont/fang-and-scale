from __future__ import annotations

from pathlib import Path

import pytest

from fns.yamlio import MAX_BYTES, YamlError, load_yaml, loads_yaml


def test_plain_mapping() -> None:
    assert loads_yaml("a: 1\nb: [x, y]\nc: true\n") == {"a": 1, "b": ["x", "y"], "c": True}


def test_duplicate_key_rejected() -> None:
    with pytest.raises(YamlError, match="duplicate key 'tenant_id'"):
        loads_yaml("tenant_id: a\nother: 1\ntenant_id: b\n")


def test_nested_duplicate_key_rejected() -> None:
    with pytest.raises(YamlError, match="duplicate key"):
        loads_yaml("outer:\n  k: 1\n  k: 2\n")


def test_aliases_and_anchors_rejected() -> None:
    with pytest.raises(YamlError, match="anchors"):
        loads_yaml("a: &x [1, 2]\nb: *x\n")


def test_alias_bomb_rejected_quickly() -> None:
    bomb = 'a: &a ["x","x"]\nb: &b [*a,*a]\nc: &c [*b,*b]\nd: [*c,*c]\n'
    with pytest.raises(YamlError):
        loads_yaml(bomb)


def test_timestamps_stay_strings() -> None:
    assert loads_yaml("t: 2026-12-01T00:00:00Z\nd: 2026-12-01\n") == {
        "t": "2026-12-01T00:00:00Z",
        "d": "2026-12-01",
    }


@pytest.mark.parametrize("word", ["yes", "no", "on", "off", "True", "FALSE", "y", "n"])
def test_yaml11_booleans_stay_strings(word: str) -> None:
    assert loads_yaml(f"v: {word}\n") == {"v": word}


@pytest.mark.parametrize("doc", ["- a\n- b\n", "just a string\n", "", "a: 1\n---\nb: 2\n"])
def test_top_level_must_be_single_mapping(doc: str) -> None:
    with pytest.raises(YamlError):
        loads_yaml(doc)


def test_python_tags_rejected() -> None:
    with pytest.raises(YamlError):
        loads_yaml("a: !!python/object/apply:os.system ['echo hi']\n")


def test_size_limit(tmp_path: Path) -> None:
    big = tmp_path / "big.yaml"
    big.write_text("a: " + "x" * (MAX_BYTES + 1) + "\n", encoding="utf-8")
    with pytest.raises(YamlError, match="1 MiB"):
        load_yaml(big)


def test_syntax_error_wrapped() -> None:
    with pytest.raises(YamlError):
        loads_yaml("a: [unclosed\n")
