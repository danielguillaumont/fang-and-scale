"""Refuse a release whose tag, package version and changelog disagree.

Usage: ``python scripts/release_check.py v0.1.0`` (the release workflow passes the
tag), or with no argument to check the version and changelog only
(``uv run poe release-check``). Standard library only, so it runs before install.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def problems(tag: str | None) -> list[str]:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    out: list[str] = []
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        out.append(f"pyproject version {version!r} is not MAJOR.MINOR.PATCH")
    if tag is not None and tag != f"v{version}":
        out.append(f"tag {tag!r} does not match pyproject version {version!r}")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.search(rf"^## \[{re.escape(version)}\] - (.+)$", changelog, re.M)
    if heading is None:
        out.append(f"CHANGELOG.md has no '## [{version}] - <date>' section")
    elif tag is not None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", heading[1].strip()):
        out.append(f"CHANGELOG.md's [{version}] section needs its release date, not {heading[1]!r}")
    if f"[{version}]: https://github.com/" not in changelog:
        out.append(f"CHANGELOG.md has no link for [{version}]")
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    if not re.search(rf'name = "fang-and-scale"\nversion = "{re.escape(version)}"', lock):
        out.append("uv.lock is not locked at the pyproject version (run uv lock)")
    return out


def main(argv: list[str]) -> int:
    found = problems(argv[1] if len(argv) > 1 else None)
    for p in found:
        sys.stderr.write(f"release check: {p}\n")
    if not found:
        sys.stdout.write("release check: ok\n")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
