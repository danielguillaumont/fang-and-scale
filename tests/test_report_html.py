"""Static HTML report: consistent inputs, escaping of tenant data, CSP, determinism."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fns.cli import app
from fns.contain_run import demo_contract, run_demo_contain
from fns.fixtures.replay import bundled
from fns.models.report import ContainReport
from fns.mutate_cli import run as run_mutation
from fns.report.html import (
    CYTOSCAPE_FILE,
    CYTOSCAPE_SRI,
    SCRIPT,
    Inputs,
    ReportInputError,
    check,
    cytoscape_js,
    graph_elements,
    render_html,
)

ROOT = Path(__file__).resolve().parents[1]
LAB_RUN = ROOT / "fixtures" / "lab-run-1"
LAB = ROOT / "lab"
runner = CliRunner()


@pytest.fixture(scope="module")
def lab_report(tmp_path_factory: pytest.TempPathFactory) -> ContainReport:
    _, report = run_demo_contain(tmp_path_factory.mktemp("lab"), LAB_RUN)
    return report


def test_graph_is_a_prefix_tree_with_one_leaf_per_finding(lab_report: ContainReport) -> None:
    els = graph_elements(lab_report)
    nodes = {e["data"]["id"] for e in els if "source" not in e["data"]}
    edges = [e["data"] for e in els if "source" in e["data"]]
    assert all(e["source"] in nodes and e["target"] in nodes for e in edges)
    roots = [e for e in els if e.get("classes") == "root"]
    assert len(roots) == 1
    with_paths = {p.finding_id for p in lab_report.paths}
    leaves = [e for e in els if str(e.get("classes", "")).startswith("finding")]
    assert len(leaves) == len(with_paths)
    steps = sum(len(p.steps) for p in lab_report.paths if p.rank == 0)
    assert len(nodes) - len(leaves) < steps  # shared prefixes merged
    assert graph_elements(lab_report) == els


def test_page_leads_with_coverage_and_is_deterministic(lab_report: ContainReport) -> None:
    page = render_html(Inputs(lab_report))
    assert page == render_html(Inputs(lab_report))
    assert page.index('id="coverage"') < page.index('id="graph-h"') < page.index('id="findings"')
    assert "FIXTURE: replayed" in page and "<title>FIXTURE" in page
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    assert f"'sha256-{script_hash}'" in page
    assert f"<script>{SCRIPT}</script>" in page


def _sha(algo: str, data: bytes) -> str:
    return base64.b64encode(hashlib.new(algo, data).digest()).decode()


def test_vendored_cytoscape_is_the_pinned_file() -> None:
    data = (ROOT / "src" / "fns" / "report" / "vendor" / CYTOSCAPE_FILE).read_bytes()
    assert f"sha384-{_sha('sha384', data)}" == CYTOSCAPE_SRI
    assert (ROOT / "src" / "fns" / "report" / "vendor" / "cytoscape-3.30.2.LICENSE").is_file()
    assert data.startswith(b"/**\n * Copyright (c) 2016-2024, The Cytoscape Consortium.")


def test_report_renders_offline(lab_report: ContainReport) -> None:
    page = render_html(Inputs(lab_report))
    assert f"<script>{cytoscape_js()}</script>" in page
    own = page.replace(cytoscape_js(), "")  # its licence comments name web sites
    assert "http://" not in own and "https://" not in own and "cdnjs" not in own
    assert " src=" not in own and " href=" not in own
    assert "Permission is hereby granted" in page  # the MIT notice travels with the code
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', page)
    assert csp
    hashes = re.findall(r"'sha256-([A-Za-z0-9+/=]+)'", csp.group(1))
    assert hashes == [_sha("sha256", cytoscape_js().encode()), _sha("sha256", SCRIPT.encode())]
    assert "https:" not in csp.group(1) and "connect-src 'none'" in csp.group(1)


def test_tenant_strings_are_escaped(lab_report: ContainReport) -> None:
    hostile = "<img src=x onerror=alert(1)></script><script>alert(2)</script>"
    first = lab_report.paths[0]
    steps = (first.steps[0].model_copy(update={"text": hostile}), *first.steps[1:])
    evil = lab_report.model_copy(
        update={
            "compromised_name": hostile,
            "paths": (first.model_copy(update={"steps": steps}), *lab_report.paths[1:]),
        }
    )
    page = render_html(Inputs(evil))
    assert "<img src=x" not in page
    assert "alert(2)</script>" not in page
    data = re.search(r'<script type="application/json" id="fns-graph">(.*?)</script>', page, re.S)
    assert data is not None
    assert "<" not in data.group(1)
    assert hostile in json.dumps(json.loads(data.group(1)))  # round-trips intact


def test_refuses_to_mix_runs(lab_report: ContainReport, tmp_path: Path) -> None:
    _, other = run_demo_contain(tmp_path / "demo")
    mutation = run_mutation(
        demo_contract(None),
        _snapshot(tmp_path / "s"),
        None,
        harden=False,
        now=datetime(2026, 11, 26, tzinfo=UTC),
    )
    assert check(Inputs(lab_report, mutation)) != []
    assert check(Inputs(other, mutation)) == []
    with pytest.raises(ReportInputError, match="different snapshot"):
        render_html(Inputs(lab_report, mutation))


def _snapshot(out: Path):  # type: ignore[no-untyped-def]
    scout, _ = run_demo_contain(out)
    return scout.snapshot


def test_demo_report_with_proof_and_mutation(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["demo", "report", "--fixture", str(LAB_RUN), "--lab", str(LAB), "--out", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    assert all(line.startswith("FIXTURE ") for line in result.output.splitlines() if line.strip())
    page = (tmp_path / "report.FIXTURE.html").read_text(encoding="utf-8")
    assert "Mutation score 5/8" in page
    assert "TEST SIGNATURE" in page
    assert "passed with evidence" in page
    assert "after prove" in page


def test_cli_report_from_files(tmp_path: Path) -> None:
    contain = tmp_path / "contain.json"
    r = runner.invoke(
        app,
        [
            "demo",
            "contain",
            "--fixture",
            str(LAB_RUN),
            "--out",
            str(tmp_path),
            "--json",
            str(contain),
        ],
    )
    assert r.exit_code == 1, r.output
    r = runner.invoke(app, ["demo", "prove", "--fixture", str(LAB_RUN), "--out", str(tmp_path)])
    (run_dir,) = (tmp_path / "runs").iterdir()
    mutation = tmp_path / "mutation.json"
    runner.invoke(
        app,
        [
            "demo",
            "mutate",
            "--fixture",
            str(LAB_RUN),
            "--lab",
            str(LAB),
            "--out",
            str(tmp_path),
            "--json",
            str(mutation),
        ],
    )
    out = tmp_path / "r.html"
    args = ["report", "--contain", str(contain), "--prove", str(run_dir), "--out", str(out)]
    ok = runner.invoke(app, [*args, "--mutation", str(mutation)])
    assert ok.exit_code == 0, ok.output
    assert "contain + prove + mutation" in ok.output
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")

    demo_contain = tmp_path / "demo-contain.json"
    runner.invoke(
        app,
        [
            *("demo", "contain", "--out", str(tmp_path / "d")),
            *("--json", str(demo_contain), "--fixture", str(bundled("demo-scout"))),
        ],
    )
    mixed = runner.invoke(app, ["report", "--contain", str(demo_contain), "--prove", str(run_dir)])
    assert mixed.exit_code == 2
    assert "refusing to mix runs" in mixed.output
    missing = runner.invoke(app, ["report", "--contain", str(tmp_path / "nope.json")])
    assert missing.exit_code == 2
