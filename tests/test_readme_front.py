"""The README's front page stays generated, current and honest.

- The demo block is real ``fns demo contain --bundled`` output, cut only by
  ``scripts/render_images.py``; every kept line is an output line, unchanged.
- ``docs/sample-report/report.FIXTURE.html`` is byte for byte what ``fns demo
  report`` writes today, and labelled FIXTURE.
- The images exist at the sizes the README and GitHub expect.
- The badges point at workflows that exist, and no stale release claim is left.
"""

from __future__ import annotations

import importlib.util
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
_spec = importlib.util.spec_from_file_location(
    "render_images", ROOT / "scripts" / "render_images.py"
)
assert _spec is not None and _spec.loader is not None
render = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render)


def _png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", path
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def test_the_demo_block_is_the_generated_output() -> None:
    assert render.updated_readme(README) == README, (
        "the README demo block drifted: uv run python scripts/render_images.py"
    )


def test_every_kept_line_is_a_real_output_line_in_order() -> None:
    code, lines = render.demo_lines()
    assert code == 1  # the demo contract fails on purpose
    kept = [ln for ln in render.excerpt(lines) if ln != render.ELIDED]
    at = -1
    for ln in kept:  # each kept line appears in the output after the previous one
        at = lines.index(ln, at + 1)
    assert all(ln.startswith("FIXTURE") for ln in kept)
    assert not any("Replaying fixture" in ln for ln in kept)  # names the local checkout
    assert kept[-1] == "FIXTURE contract FAILED (exit 1)"


def test_the_sample_report_is_what_fns_demo_report_writes() -> None:
    committed = render.SAMPLE_HTML.read_bytes()
    assert render.sample_report() == committed, (
        "docs/sample-report drifted: uv run python scripts/render_images.py"
    )
    text = committed.decode("utf-8")
    assert "<title>FIXTURE" in text
    assert "FIXTURE: replayed from recorded or hand-written files, not a live tenant." in text


def test_the_images_have_the_expected_sizes() -> None:
    assert _png_size(render.SOCIAL_PNG) == (1280, 640)
    assert _png_size(render.SAMPLE_PNG)[0] == 1280
    assert "docs/sample-report/report.png" in README
    assert "docs/sample-report/report.FIXTURE.html" in README


def test_the_badges_point_at_real_workflows() -> None:
    badges = re.findall(r"actions/workflows/([\w-]+\.yml)/badge\.svg", README)
    assert badges == ["ci.yml", "codeql.yml"]
    for name in badges:
        assert (ROOT / ".github" / "workflows" / name).is_file(), name
    head = README.split("## Why", 1)[0]
    for needed in ("release", "license", "python-3.12", "attested"):
        assert needed in head, needed


def test_the_proven_live_table_keeps_m4_pending() -> None:
    section = README.split("## Proven live", 1)[1].split("\n## ", 1)[0]
    row = "| M4 harden, strikes, detections | pending | "
    assert f"{row}**built and tested offline, live run pending**" in section
    for date in ("2026-11-26", "2026-11-27"):
        assert date in section


def test_no_stale_release_claim_is_left() -> None:
    quickstart = (ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
    for doc in (README, quickstart):
        for stale in ("not tagged", "Until the `v0.1.0` tag exists", "no release yet"):
            assert stale not in doc, stale
    assert "v0.1.0 released 2026-11-27" in README


def test_the_release_verification_matches_the_release_files() -> None:
    section = README.split("## Install and verify the release", 1)[1].split("\n## ", 1)[0]
    wheel = "fang_and_scale-0.1.0-py3-none-any.whl"
    assert f"gh attestation verify fns-0.1.0/{wheel} -R danielguillaumont/fang-and-scale" in section
    assert f"pipx install --python 3.12 fns-0.1.0/{wheel}" in section
