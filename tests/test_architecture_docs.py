"""docs/ARCHITECTURE.md and docs/THREAT-MODEL.md stay true as the code moves.

The docs name files, packages, tests and import contracts as the things that
enforce each boundary. If one is renamed or removed, the doc is wrong, and this
test says which name to fix.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from fns.exitcodes import ExitCode

ROOT = Path(__file__).resolve().parents[1]
ARCH = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
THREAT = (ROOT / "docs" / "THREAT-MODEL.md").read_text(encoding="utf-8")
CONTRACTS = [
    c["name"]
    for c in tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "importlinter"
    ]["contracts"]
]
DOCS = {"ARCHITECTURE": ARCH, "THREAT-MODEL": THREAT}


def _paths(text: str) -> set[str]:
    return set(re.findall(r"`((?:tests|src|docs|\.github)/[\w./-]+\.(?:py|md|yml))`", text))


def _modules(text: str) -> set[str]:
    return set(re.findall(r"`(fns(?:\.\w+)+)`", text))


@pytest.mark.parametrize("doc", DOCS)
def test_every_named_file_exists(doc: str) -> None:
    named = _paths(DOCS[doc])
    assert named, doc
    missing = sorted(p for p in named if not (ROOT / p).is_file())
    assert not missing, f"{doc} names files that do not exist: {missing}"


@pytest.mark.parametrize("doc", DOCS)
def test_every_named_module_exists(doc: str) -> None:
    missing = []
    for name in _modules(DOCS[doc]):
        parts = name.split(".")
        # `fns.prove.run.verifier_env`: the longest prefix that is a module, then names in it.
        for cut in range(len(parts), 1, -1):
            base = ROOT / "src" / Path(*parts[:cut])
            if base.with_suffix(".py").is_file() or (base / "__init__.py").is_file():
                rest = parts[cut:]
                src = (
                    base.with_suffix(".py")
                    if base.with_suffix(".py").is_file()
                    else base / "__init__.py"
                )
                if rest and not re.search(
                    rf"^(?:def|class|\s+def) {re.escape(rest[0])}\b|^{re.escape(rest[0])}\b",
                    src.read_text(encoding="utf-8"),
                    re.M,
                ):
                    missing.append(name)
                break
        else:
            missing.append(name)
    assert not missing, f"{doc} names modules that do not exist: {sorted(missing)}"


def test_every_import_contract_is_named() -> None:
    text = " ".join(ARCH.split())
    for name in CONTRACTS:
        assert f'"{name}"' in text, f"ARCHITECTURE does not name the import contract {name!r}"


def test_the_exit_code_table_matches_the_code() -> None:
    rows = dict(re.findall(r"^\| (\d) \| ([^|]+) \|$", ARCH, re.M))
    assert sorted(int(k) for k in rows) == sorted({int(c) for c in ExitCode})


def test_the_threat_model_covers_each_hostile_input_and_says_what_does_not_hold() -> None:
    for heading in (
        "A malicious tool",
        "A malicious fixture",
        "A malicious scope file",
        "A malicious contract",
        "Hostile tenant data",
        "A forged or tampered run directory",
        "A hostile pull request",
        "Open gaps",
    ):
        assert re.search(rf"^## (?:\d\. )?{re.escape(heading)}$", THREAT, re.M), heading
    # Every numbered section is honest about its limits.
    sections = re.split(r"^## \d\. ", THREAT, flags=re.M)[1:]
    assert len(sections) == 7
    for s in sections:
        assert "**What does not" in s, s.splitlines()[0]


def test_the_docs_are_linked() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/ARCHITECTURE.md" in readme and "docs/THREAT-MODEL.md" in readme
    assert "THREAT-MODEL.md" in ARCH and "ARCHITECTURE.md" in THREAT
