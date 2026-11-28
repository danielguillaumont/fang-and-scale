"""Regenerate the README's generated parts from the bundled and recorded fixtures.

    uv run python scripts/render_images.py            # write everything
    uv run python scripts/render_images.py --check    # exit 1 if a text part drifted

It writes:

- the README block between ``<!-- demo-output:begin -->`` and ``<!-- demo-output:end -->``:
  real lines from ``fns demo contain --bundled``, abbreviated, never retyped;
- ``docs/sample-report/report.FIXTURE.html``: ``fns demo report`` on
  ``fixtures/lab-run-3`` (byte for byte reproducible);
- ``docs/sample-report/report.png`` and ``docs/social-preview.png``: screenshots
  taken with a headless Chrome or Edge, if one is found (set ``FNS_CHROME`` to its
  path). Without one, the PNGs are left as they are and the script says so.

``tests/test_readme_front.py`` regenerates the text parts and fails on drift.
Everything here replays files; nothing touches a tenant.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SAMPLE_DIR = ROOT / "docs" / "sample-report"
SAMPLE_HTML = SAMPLE_DIR / "report.FIXTURE.html"
SAMPLE_PNG = SAMPLE_DIR / "report.png"
SOCIAL_HTML = ROOT / "docs" / "assets" / "social-preview.html"
SOCIAL_PNG = ROOT / "docs" / "social-preview.png"
BEGIN, END = "<!-- demo-output:begin -->", "<!-- demo-output:end -->"
DEMO_COMMAND = "fns demo contain --bundled"
ELIDED = "[...]"
PATH_SHOWN = "FAIL directory:tenant roleAssignments/write"
CHROMES = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


def _fns(*args: str, cwd: Path) -> tuple[int, str]:
    env = {**os.environ, "COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}
    done = subprocess.run(  # noqa: S603 - our own CLI, fixed arguments
        [sys.executable, "-m", "fns", *args],
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # one stream, in the order a terminal shows it
        text=True,
        encoding="utf-8",
        check=False,
    )
    return done.returncode, done.stdout


def demo_lines() -> tuple[int, list[str]]:
    """The real output of ``fns demo contain --bundled``, run in an empty directory."""
    with tempfile.TemporaryDirectory() as tmp:
        code, out = _fns("demo", "contain", "--bundled", "--out", "o", cwd=Path(tmp))
    return code, [ln.rstrip() for ln in out.splitlines() if ln.strip()]


def _provenance(line: str) -> bool:
    return line.startswith(("FIXTURE        from ", "FIXTURE      assumes"))


def excerpt(lines: list[str]) -> list[str]:
    """Keep the header, the findings table, one escalation path and the verdict.

    Every kept line is a line of the output, unchanged. ``[...]`` marks a cut, except
    for the per-step provenance lines of the path (``from ...``, ``assumes ...``),
    which are left out silently. The fixture path line is cut: it names the local
    checkout.
    """
    keep: set[int] = set()
    for i, ln in enumerate(lines):
        if ln.startswith("FIXTURE replaying") or re.match(
            r"FIXTURE (contract |snapshot |evidence:|coverage:|critical reachable:)", ln
        ):
            keep.add(i)
    keep.update(range(lines.index("FIXTURE Findings"), lines.index("FIXTURE Escalation paths")))
    path = lines.index(f"FIXTURE {PATH_SHOWN}  modeled / modeled-only")
    keep.add(path)
    for i in range(path + 1, len(lines)):
        if re.match(r"FIXTURE   \d+\. ", lines[i]):
            keep.add(i)
        elif not _provenance(lines[i]):
            break
    out: list[str] = []
    prev: int | None = None
    for i in sorted(keep):
        gap = range(prev + 1, i) if prev is not None else range(0)
        if gap and not all(_provenance(lines[j]) for j in gap):
            out.append(ELIDED)
        out.append(lines[i])
        prev = i
    return out


def readme_block() -> str:
    code, lines = demo_lines()
    if code != 1:
        raise SystemExit(f"{DEMO_COMMAND} exited {code}, expected 1:\n" + "\n".join(lines))
    body = "\n".join(excerpt(lines))
    return f"{BEGIN}\n```\n$ {DEMO_COMMAND}\n{body}\n$ echo $?\n1\n```\n{END}"


def updated_readme(text: str) -> str:
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
    if not pattern.search(text):
        raise SystemExit(f"README.md has no {BEGIN} ... {END} block")
    return pattern.sub(lambda _: readme_block(), text, count=1)


def sample_report() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        code, out = _fns("demo", "report", "--out", str(Path(tmp) / "o"), cwd=ROOT)
        if code not in (0, 1):
            raise SystemExit(f"fns demo report exited {code}:\n{out}")
        return (Path(tmp) / "o" / "report.FIXTURE.html").read_bytes()


def _chrome() -> str | None:
    found = os.environ.get("FNS_CHROME")
    if found:
        return found
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge"):
        path = shutil.which(name)
        if path:
            return path
    return next((p for p in CHROMES if Path(p).is_file()), None)


def screenshot(chrome: str, page: Path, out: Path, width: int, height: int) -> None:
    with tempfile.TemporaryDirectory() as profile:
        subprocess.run(  # noqa: S603 - a local browser on a local file
            [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--hide-scrollbars",
                "--no-first-run",
                f"--user-data-dir={profile}",
                f"--window-size={width},{height}",
                "--virtual-time-budget=8000",
                f"--screenshot={out}",
                page.resolve().as_uri(),
            ],
            check=True,
            capture_output=True,
        )


def main(argv: list[str]) -> int:
    check = "--check" in argv
    readme_now = README.read_text(encoding="utf-8")
    readme_new = updated_readme(readme_now)
    html_new = sample_report()
    html_now = SAMPLE_HTML.read_bytes() if SAMPLE_HTML.is_file() else b""
    if check:
        drift = [
            n
            for n, ok in (
                ("README.md", readme_new == readme_now),
                (str(SAMPLE_HTML.relative_to(ROOT)), html_new == html_now),
            )
            if not ok
        ]
        for name in drift:
            sys.stderr.write(f"{name} drifted: uv run python scripts/render_images.py\n")
        return 1 if drift else 0
    README.write_text(readme_new, encoding="utf-8", newline="\n")
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLE_HTML.write_bytes(html_new)
    chrome = _chrome()
    if chrome is None:
        sys.stdout.write("no headless Chrome or Edge found: the PNGs were not regenerated\n")
        return 0
    screenshot(chrome, SAMPLE_HTML, SAMPLE_PNG, 1280, 1100)
    screenshot(chrome, SOCIAL_HTML, SOCIAL_PNG, 1280, 640)
    sys.stdout.write(f"wrote {SAMPLE_PNG.relative_to(ROOT)} and {SOCIAL_PNG.relative_to(ROOT)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
