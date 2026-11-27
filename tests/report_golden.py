"""The strike-demo report golden (``tests/golden/report-strike-demo.html``).

Built from FIXTURE files only, through the real commands:

1. ``fns demo contain`` and ``fns demo prove`` on the bundled ``demo-scout``, the
   prove with ``--after-strike`` from step 2's after-harden run;
2. ``fns strike plan`` and ``run --fixture fixtures/strike-demo``, before harden
   (S1 to S3) and after (D-1 to D-5);
3. ``fns report`` with both strike runs and ``fixtures/strike-demo/detections.yaml``.

The golden is the page's ``<main>`` element, with the tool version blanked; the
scripts and styles around it are covered by ``tests/test_report_html.py``.
Regenerate only for a change meant to alter the page, and say so in the PR:
``uv run python -m tests.report_golden``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from typer.testing import CliRunner

from fns.cli import app
from fns.fixtures.replay import bundled

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "report-strike-demo.html"
STRIKE_FIXTURE = ROOT / "fixtures" / "strike-demo"
DETECTIONS = STRIKE_FIXTURE / "detections.yaml"
HASH = re.compile(r"plan sha256:([0-9a-f]{64})")
runner = CliRunner()


def _ok(args: list[str], codes: frozenset[int] = frozenset({0})) -> str:
    r = runner.invoke(app, args)
    assert r.exit_code in codes, (args, r.exit_code, r.output)
    return r.output


def strike_run(out: Path, strikes: str) -> Path:
    fixture = ["--fixture", STRIKE_FIXTURE.as_posix()]
    planned = _ok(["strike", "plan", "--strikes", strikes, *fixture, "--out", str(out)])
    m = HASH.search(planned)
    assert m is not None
    (plan,) = out.glob("*/plan.json")
    _ok(["strike", "run", "--plan", str(plan), "--approve", m[1], *fixture])
    return plan.parent


def build(tmp: Path) -> tuple[str, dict[str, Path]]:
    demo = Path(str(bundled("demo-scout")))
    before = strike_run(tmp / "strike-before", "S1,S2,S3")
    after = strike_run(tmp / "strike-after", "D-1,D-2,D-3,D-4,D-5")
    contain = tmp / "contain.json"
    work = tmp / "work"
    proved = frozenset({0, 1, 3})
    _ok(
        ["demo", "contain", "--fixture", str(demo), "--out", str(work), "--json", str(contain)],
        proved,
    )
    _ok(
        ["demo", "prove", "--fixture", str(demo), "--out", str(work), "--after-strike", str(after)],
        proved,
    )
    (run_dir,) = (work / "runs").iterdir()
    page_file = tmp / "report.html"
    _ok(
        [
            *("report", "--contain", str(contain), "--prove", str(run_dir)),
            *("--strike", str(before), "--strike", str(after)),
            *("--detections", str(DETECTIONS), "--out", str(page_file)),
        ]
    )
    paths = {"contain": contain, "run": run_dir, "before": before, "after": after}
    return page_file.read_text(encoding="utf-8"), paths


def main_element(page: str) -> str:
    m = re.search(r"<main>.*</main>", page, re.S)
    assert m is not None
    text = re.sub(r"fns \d+\.\d+\.\d+\S*,", "fns <version>,", m[0])
    return text.replace("><", ">\n<") + "\n"


def main() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        page, _ = build(Path(tmp))
    GOLDEN.write_text(main_element(page), encoding="utf-8", newline="\n")
    sys.stdout.write(f"wrote {GOLDEN.relative_to(ROOT)}\n")


if __name__ == "__main__":
    main()
