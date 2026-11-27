"""CLAUDE.md rule 6: no real tenant identifiers or secrets in any fixture.

Scans every file under both fixture roots (recorded lab runs in ``fixtures/``
and the bundled demo in ``src/fns/fixtures/data/``) plus test data.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from fns.fixtures.sanitize import EMAIL_RE, GUID_RE, JWT_RE, PLACEHOLDER_RE, SAFE_EMAIL_SUFFIX
from fns.fixtures.wellknown import WELL_KNOWN_GUIDS

ROOT = Path(__file__).resolve().parents[2]
SCANNED = [
    ROOT / "fixtures",
    ROOT / "src" / "fns" / "fixtures" / "data",
    ROOT / "contracts",
    ROOT / "detections",
]
SCANNED_FILES = [ROOT / "scope.example.yaml"]
SECRET_KEY_RE = re.compile(
    r'"(secretText|clientSecret|client_secret|password|access_token|refresh_token)"\s*:\s*"(?!REDACTED)'
)


def _files() -> list[Path]:
    out = list(SCANNED_FILES)
    for root in SCANNED:
        out.extend(p for p in root.rglob("*") if p.is_file() and p.name != "_idmap.json")
    return sorted(out)


FILES = _files()


def test_scan_covers_the_demo_fixture() -> None:
    names = {p.name for p in FILES}
    assert {"exchanges.json", "manifest.json", "scope.yaml"} <= names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_fixture_file_has_no_real_identifiers(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    bad_guids = sorted(
        {
            g
            for g in GUID_RE.findall(text)
            if g.lower() not in WELL_KNOWN_GUIDS and not PLACEHOLDER_RE.match(g.lower())
        }
    )
    assert bad_guids == [], f"non-placeholder GUIDs: {bad_guids}"
    emails = [e for e in EMAIL_RE.findall(text) if not e.lower().endswith(SAFE_EMAIL_SUFFIX)]
    assert emails == []
    assert "onmicrosoft.com" not in text.lower()
    assert not JWT_RE.search(text)
    assert not SECRET_KEY_RE.search(text)


def test_idmap_files_are_gitignored() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "**/_idmap.json" in gitignore.splitlines()
