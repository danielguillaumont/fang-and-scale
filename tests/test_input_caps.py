"""Size caps on every JSON and YAML input (threat model open gap, approved 2026-11-27).

- :mod:`fns.inputcap` refuses a file over its cap from its size, and again if it
  grows while being read; it imports nothing from ``fns`` (the verifier uses it);
- no module in ``src/fns`` reads a file any other way, apart from a short list of
  non-JSON, non-YAML reads (Terraform files, our own diff, vendored JavaScript);
- the loaders that face hostile input refuse an oversized file before parsing;
- the MCP server reads stdin a bounded line at a time.
"""

from __future__ import annotations

import ast
import io
import json
from pathlib import Path

import pytest

from fns import inputcap
from fns.contain_run import load_snapshot
from fns.fixtures.replay import FixtureSet
from fns.inputcap import (
    MAX_JSON_BYTES,
    MAX_RECORD_BYTES,
    InputTooLargeError,
    read_capped,
    read_capped_text,
)
from fns.mcp.server import MAX_LINE_BYTES, Server, serve
from fns.strike.replay import load_recording
from fns.verify.inputs import IntegrityError, read_file
from fns.yamlio import MAX_BYTES as YAML_MAX_BYTES
from fns.yamlio import YamlError, load_yaml

SRC = Path(__file__).resolve().parents[1] / "src" / "fns"
NL = chr(10)

RAW_READS_ALLOWED = {
    # (module, reads): files that are neither JSON nor YAML.
    "harden/minimize.py": 1,  # lab/*.tf
    "harden/tfmap.py": 2,  # lab/*.tf
    "mutate.py": 1,  # lab/*.tf
    "harden_cli.py": 1,  # the harden.diff it wrote, compared before rewriting
    "report/html.py": 1,  # the vendored Cytoscape script (package data)
    "inputcap.py": 0,  # reads through open(), with the cap
}


def _big(path: Path, size: int) -> Path:
    with path.open("wb") as f:
        f.truncate(size)
    return path


# --- the reader ------------------------------------------------------------------------


def test_a_file_at_the_cap_is_read(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    p.write_bytes(b"{}" + b" " * 8)
    assert read_capped(p, 10) == b"{}        "
    assert read_capped_text(p, 10).strip() == "{}"


def test_a_file_over_the_cap_is_refused_before_it_is_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = tmp_path / "x.json"
    p.write_bytes(b"x" * 11)

    def no_open(*a: object, **k: object) -> None:
        raise AssertionError("opened")

    monkeypatch.setattr(Path, "open", no_open)
    with pytest.raises(InputTooLargeError, match=r"x\.json is larger than 10 bytes"):
        read_capped(p, 10)


class _CountingBytes(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.asked: list[int] = []

    def read(self, n: int | None = -1, /) -> bytes:
        self.asked.append(-1 if n is None else n)
        return super().read(n)


class _Growing:
    """A Traversable-like source with no size to stat (package data), over the cap."""

    name = "exchanges.json"

    def __init__(self) -> None:
        self.stream = _CountingBytes(b"[" + b" " * 100 + b"]")

    def open(self, mode: str = "r") -> _CountingBytes:
        return self.stream


def test_a_source_without_a_size_is_read_at_most_cap_plus_one() -> None:
    src = _Growing()
    with pytest.raises(InputTooLargeError, match=r"exchanges\.json"):
        read_capped(src, 10)  # type: ignore[arg-type]
    assert src.stream.asked == [11]


def test_the_caps_are_ordered() -> None:
    assert YAML_MAX_BYTES < MAX_RECORD_BYTES < MAX_JSON_BYTES
    assert issubclass(InputTooLargeError, ValueError)  # every loader already maps it


def test_inputcap_imports_only_the_standard_library() -> None:
    tree = ast.parse(Path(inputcap.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module is not None and not node.module.startswith("fns"), node.module
        elif isinstance(node, ast.Import):
            assert all(not a.name.startswith("fns") for a in node.names)


# --- every read goes through it ---------------------------------------------------------


def _raw_reads(path: Path) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("read_bytes", "read_text"):
                n += 1
            if node.func.attr in ("load", "safe_load") and isinstance(node.func.value, ast.Name):
                assert node.func.value.id not in ("json", "yaml"), path  # json.load(f)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "open" or path.name == "inputcap.py", path
    return n


def test_no_module_reads_a_file_around_the_cap() -> None:
    found = {}
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        n = _raw_reads(path)
        if n or rel in RAW_READS_ALLOWED:
            found[rel] = n
    assert found == RAW_READS_ALLOWED


# --- the loaders that face hostile input ------------------------------------------------


def test_an_oversized_snapshot_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InputTooLargeError):
        load_snapshot(_big(tmp_path / "snapshot.json", MAX_JSON_BYTES + 1))


def test_an_oversized_fixture_exchange_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps({"format": "fns-fixture/1", "label": "FIXTURE"}), encoding="utf-8"
    )
    _big(tmp_path / "exchanges.json", MAX_JSON_BYTES + 1)
    with pytest.raises(ValueError, match=r"exchanges\.json is larger than|format|label"):
        FixtureSet.load(tmp_path)


def test_an_oversized_strike_recording_is_refused(tmp_path: Path) -> None:
    _big(tmp_path / "before-harden.json", MAX_JSON_BYTES + 1)
    with pytest.raises(InputTooLargeError):
        load_recording(tmp_path, "before-harden")


def test_the_verifier_refuses_an_oversized_run_file(tmp_path: Path) -> None:
    with pytest.raises(IntegrityError, match=r"cannot read bundle\.json"):
        read_file(_big(tmp_path / "bundle.json", MAX_RECORD_BYTES + 1))


def test_yaml_keeps_its_1_mib_cap(tmp_path: Path) -> None:
    with pytest.raises(YamlError, match="exceeds 1 MiB"):
        load_yaml(_big(tmp_path / "scope.yaml", YAML_MAX_BYTES + 1))


# --- MCP stdin ---------------------------------------------------------------------------


class _Lines(io.StringIO):
    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.asked: list[int] = []

    def readline(self, size: int = -1, /) -> str:  # type: ignore[override]
        self.asked.append(size)
        return super().readline(size)


def test_an_endless_mcp_line_is_answered_and_skipped() -> None:
    ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    stdin = _Lines("x" * (3 * MAX_LINE_BYTES) + NL + ping + NL)
    stdout = io.StringIO()
    assert serve(Server(), stdin, stdout) == 0
    replies = [json.loads(x) for x in stdout.getvalue().splitlines()]
    assert replies[0]["error"]["code"] == -32600 and "longer than" in replies[0]["error"]["message"]
    assert replies[1] == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert stdin.asked and all(s == MAX_LINE_BYTES + 1 for s in stdin.asked)
