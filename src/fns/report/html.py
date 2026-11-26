"""Static HTML report: coverage first, then the reach graph, findings, proof and mutation.

One self-contained file. Every value from a tenant (names, step texts, sources)
is untrusted (PLAN section 9) and is escaped; the graph data is embedded as
JSON with ``<``, ``>`` and ``&`` escaped and shown with ``textContent`` only.
Cytoscape is vendored (``vendor/``, MIT) and embedded, so the page makes no network
request and renders offline. A Content-Security-Policy allows exactly two inline
scripts by hash, Cytoscape and the page's own, and nothing else; the paths are
also written out as text.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from functools import cache
from html import escape
from importlib.resources import files
from typing import Any, Final

from fns.models.bundle import EvidenceBundle
from fns.models.evidence import RUNG_ORDER, CoverageState, Finding
from fns.models.mutation import MutationReport
from fns.models.report import ContainReport

CYTOSCAPE_VERSION: Final = "3.30.2"
CYTOSCAPE_FILE: Final = f"cytoscape-{CYTOSCAPE_VERSION}.min.js"
CYTOSCAPE_SOURCE: Final = (
    f"https://cdnjs.cloudflare.com/ajax/libs/cytoscape/{CYTOSCAPE_VERSION}/cytoscape.min.js"
)
"""Where the vendored file came from (provenance only; the page never loads it)."""
CYTOSCAPE_SRI: Final = "sha384-IWROdLKRsN1UuJywMlWl7/blXQ8GEooN2n7dzTxfEPd7ybYIKCUJ2Ol/1Gpf3YV4"
"""The published SRI hash of that file; the vendored copy must match it byte for byte."""
COVERAGE_ORDER: Final[tuple[CoverageState, ...]] = (
    "verified",
    "evaluated-only",
    "modeled-only",
    "not-assessed",
    "out-of-scope",
)
COVERAGE_MEANING: Final[dict[str, str]] = {
    "verified": "a live probe observed the result",
    "evaluated-only": "the platform's permission evaluation agreed; no live probe",
    "modeled-only": "only the reach model says so",
    "not-assessed": "nothing could decide it (unmodeled surface, missing data)",
    "out-of-scope": "outside the scope manifest",
}
RUNGS: Final[tuple[tuple[str, str], ...]] = (
    ("modeled", "the reach model over a snapshot"),
    ("evaluated", "the platform's own permission evaluation"),
    ("observed", "a live, non-destructive probe"),
    ("logged", "the probe also showed up in the logs"),
)
EXIT_MEANING: Final[dict[int, str]] = {
    0: "within budget",
    1: "contract failed",
    3: "inconclusive over budget",
}


OUTCOME_CLASS: Final[dict[str, str]] = {
    "killed": "pass",
    "survived": "fail",
    "inconclusive": "inconclusive",
}


class ReportInputError(ValueError):
    pass


@dataclass(frozen=True)
class Inputs:
    contain: ContainReport
    mutation: MutationReport | None = None
    bundle: EvidenceBundle | None = None
    signing: dict[str, str] | None = None
    """``signing.json`` from the prove run: signer and its warning, if any."""


def check(inputs: Inputs) -> list[str]:
    """Refuse to put results from different runs on one page."""
    c = inputs.contain
    problems: list[str] = []
    for name, other in (("mutation", inputs.mutation), ("bundle", inputs.bundle)):
        if other is None:
            continue
        if other.mode != c.mode:
            problems.append(f"{name} is {other.mode} but the contain report is {c.mode}")
        if other.contract_digest != c.contract_digest:
            problems.append(f"{name} was made from a different contract")
        if other.snapshot_digest != c.snapshot_digest:
            problems.append(f"{name} was made from a different snapshot")
    if inputs.bundle is not None and inputs.bundle.report_digest != c.digest():
        problems.append("bundle was made from a different contain report")
    return problems


def _max_rung(f: Finding) -> str:
    rungs = [e.rung for e in f.evidence if e.outcome in {"allowed", "denied"}]
    return max(rungs, key=lambda r: RUNG_ORDER[r]) if rungs else "none"


def _safe_json(data: Any) -> str:
    text = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _node_id(prefix: tuple[str, ...]) -> str:
    return "n" + hashlib.sha256("\x1f".join(prefix).encode()).hexdigest()[:16]


def graph_elements(report: ContainReport) -> list[dict[str, Any]]:
    """Shortest path of each finding as a prefix tree: shared steps merge."""
    by_id = {f.id: f for f in report.findings}
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    for p in report.paths:
        if p.rank != 0:
            continue
        finding = by_id[p.finding_id]
        prefix: tuple[str, ...] = ()
        prev: str | None = None
        for i, step in enumerate(p.steps):
            prefix = (*prefix, step.text)
            nid = _node_id(prefix)
            if i == 0:
                kind = "root"
                label = report.compromised_name or "compromised identity"
            elif step.rule == "snapshot":
                kind, label = "fact", "fact"
            elif i == len(p.steps) - 1:
                kind, label = "way", step.rule
            else:
                kind, label = "escalation", step.rule
            nodes.setdefault(
                nid,
                {
                    "data": {
                        "id": nid,
                        "label": label,
                        "text": step.text,
                        "sources": list(step.sources),
                    },
                    "classes": kind,
                },
            )
            if prev is not None:
                eid = f"e{prev}{nid}"
                edges.setdefault(eid, {"data": {"id": eid, "source": prev, "target": nid}})
            prev = nid
        leaf = "f" + finding.id[:16]
        nodes.setdefault(
            leaf,
            {
                "data": {
                    "id": leaf,
                    "label": f"{finding.target.split(':', 1)[-1]} {finding.operation}",
                    "text": f"{finding.verdict.upper()}: {finding.target} {finding.operation} "
                    f"({finding.coverage}, rung {_max_rung(finding)})",
                    "sources": [],
                },
                "classes": f"finding {finding.verdict}",
            },
        )
        if prev is not None:
            eid = f"e{prev}{leaf}"
            edges.setdefault(eid, {"data": {"id": eid, "source": prev, "target": leaf}})
    return [nodes[k] for k in sorted(nodes)] + [edges[k] for k in sorted(edges)]


CSS: Final = """
:root{--bg:#0E1116;--fg:#ECE8DF;--muted:#9AA3AE;--line:#2A303A;--panel:#151A22;
--venom:#B8F03A;--copper:#B87333;--slate:#5B6573;--fail:#E5484D;--mono:ui-monospace,
SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:light){:root{--bg:#ECE8DF;--fg:#0E1116;--muted:#4A525C;
--line:#CFC9BC;--panel:#F6F3EC;--venom:#4E7A00;--copper:#8A5320;--fail:#C0262D}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;flex-wrap:wrap;gap:8px 24px;align-items:baseline;border-bottom:1px solid
var(--line);padding-bottom:12px}.mark{font-weight:800;letter-spacing:.14em}
.tag{color:var(--muted)}h2{margin:36px 0 8px;font-size:1.15rem}h3{font-size:1rem;margin:16px 0 6px}
.fixture{background:var(--copper);color:#0E1116;font-weight:700;padding:6px 12px;margin:16px 0;
border-radius:4px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
gap:12px;margin-top:16px}.card{background:var(--panel);border:1px solid var(--line);
border-radius:6px;padding:12px}.card b{display:block;font-size:1.35rem}
.card span{color:var(--muted);
font-size:.85rem}.fail{color:var(--fail)}.pass{color:var(--venom)}.inconclusive{color:var(--copper)}
.muted{color:var(--muted)}table{width:100%;border-collapse:collapse;font-size:.92rem}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}.wrap{overflow-x:auto}code,pre{font-family:var(--mono);
font-size:.85rem}pre{background:var(--panel);border:1px solid var(--line);padding:10px;
overflow-x:auto;border-radius:4px}details{background:var(--panel);border:1px solid var(--line);
border-radius:6px;padding:8px 12px;margin:8px 0}summary{cursor:pointer}
#graph{height:520px;border:1px solid var(--line);border-radius:6px;background:var(--panel)}
#graph.off{display:none}#graph-detail{min-height:3em;margin-top:8px;white-space:pre-wrap}
.chips{display:flex;flex-wrap:wrap;gap:8px}.chip{border:1px solid var(--line);border-radius:999px;
padding:2px 10px;font-size:.85rem}ol.steps li{margin:2px 0}.rule{font-family:var(--mono);
color:var(--muted)}footer{margin-top:48px;color:var(--muted);font-size:.85rem}
"""

SCRIPT: Final = """(function(){
var el=document.getElementById('graph'),out=document.getElementById('graph-detail');
var data=JSON.parse(document.getElementById('fns-graph').textContent);
if(!window.cytoscape||!data.length){el.classList.add('off');
out.textContent=data.length?'Graph library not loaded; the paths are listed below.':'';return;}
var s=getComputedStyle(document.documentElement);function v(n){return s.getPropertyValue(n).trim();}
var cy=cytoscape({container:el,elements:data,wheelSensitivity:0.2,
layout:{name:'breadthfirst',directed:true,roots:'.root',spacingFactor:1.35},
style:[{selector:'node',style:{'label':'data(label)','color':v('--fg'),'font-size':10,
'text-valign':'bottom','text-margin-y':4,'background-color':v('--slate'),'width':18,'height':18,
'text-wrap':'ellipsis','text-max-width':110}},
{selector:'.root',style:{'background-color':v('--fg'),'width':26,'height':26}},
{selector:'.escalation',style:{'border-width':3,'border-color':v('--fail')}},
{selector:'.way',style:{'shape':'diamond'}},
{selector:'.finding',style:{'shape':'round-rectangle','width':22,'height':22}},
{selector:'.fail',style:{'background-color':v('--fail')}},
{selector:'.inconclusive',style:{'background-color':v('--copper')}},
{selector:'edge',style:{'width':1.5,'line-color':v('--slate'),'target-arrow-color':v('--slate'),
'target-arrow-shape':'triangle','curve-style':'bezier'}}]});
cy.on('tap','node',function(e){var d=e.target.data();
out.textContent=d.text+(d.sources.length?'\\n'+d.sources.join('\\n'):'');});
})();"""


class VendorError(RuntimeError):
    """The vendored Cytoscape file is missing or differs from the pinned hash."""


@cache
def cytoscape_js() -> str:
    """The vendored Cytoscape, checked against the pinned SRI hash before use."""
    data = files("fns.report").joinpath("vendor", CYTOSCAPE_FILE).read_bytes()
    actual = "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()
    if actual != CYTOSCAPE_SRI:
        raise VendorError(f"vendor/{CYTOSCAPE_FILE} is {actual}, expected {CYTOSCAPE_SRI}")
    text = data.decode("utf-8")
    if "</script" in text.lower() or "<!--" in text:
        raise VendorError(f"vendor/{CYTOSCAPE_FILE} cannot be embedded in a script element")
    return text


def _sha256(script: str) -> str:
    return base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()


def _csp() -> str:
    return (
        "default-src 'none'; img-src data:; style-src 'unsafe-inline'; "
        f"script-src 'sha256-{_sha256(cytoscape_js())}' 'sha256-{_sha256(SCRIPT)}'; "
        "connect-src 'none'; base-uri 'none'; form-action 'none'"
    )


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _cls(verdict: str) -> str:
    return {"fail": "fail", "pass": "pass", "inconclusive": "inconclusive"}.get(verdict, "")


def _coverage(findings: tuple[Finding, ...], source: str) -> str:
    counts = Counter(f.coverage for f in findings)
    chips = "".join(
        f'<span class="chip" title="{_e(COVERAGE_MEANING[c])}">{_e(c)} {counts.get(c, 0)}</span>'
        for c in COVERAGE_ORDER
    )
    rows = "".join(
        f"<tr><td>{_e(f.item_kind)}</td><td><code>{_e(f.target)}</code></td>"
        f"<td><code>{_e(f.operation)}</code></td>"
        f'<td class="{_cls(f.verdict)}">{_e(f.verdict)}</td><td>{_e(f.coverage)}</td>'
        f"<td>{_e(_max_rung(f))}</td></tr>"
        for f in sorted(findings, key=lambda f: (f.item_kind, f.target, f.operation))
    )
    return (
        f'<h2 id="coverage">Coverage</h2><p class="muted">{_e(source)}. Coverage states say how '
        "much was actually checked; read them before the verdicts.</p>"
        f'<div class="chips">{chips}</div><div class="wrap"><table><thead><tr><th>item</th>'
        "<th>target</th><th>operation</th><th>verdict</th><th>coverage</th><th>highest rung</th>"
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


def _findings(report: ContainReport, proved: dict[str, Finding]) -> str:
    paths: dict[str, list[Any]] = {}
    for p in report.paths:
        paths.setdefault(p.finding_id, []).append(p)
    parts = [
        '<h2 id="findings">Findings and paths</h2><p class="muted">Verdicts here are from the '
        "reach model (`fns contain`)"
        + ("; the verdict after `fns prove` is shown beside each." if proved else ".")
        + "</p>"
    ]
    for f in sorted(report.findings, key=lambda f: (f.item_kind, f.target, f.operation)):
        reasons = "".join(f"<li>{_e(r)}</li>" for r in f.reasons)
        evidence = "".join(
            f"<tr><td>{_e(e.rung)}</td><td>{_e(e.outcome)}</td><td><code>{_e(e.source)}</code>"
            f"</td><td>{_e(e.notes or '')}</td></tr>"
            for e in f.evidence
        )
        body = [f"<ul>{reasons}</ul>"]
        if evidence:
            body.append(
                '<div class="wrap"><table><thead><tr><th>rung</th><th>outcome</th><th>source</th>'
                f"<th>notes</th></tr></thead><tbody>{evidence}</tbody></table></div>"
            )
        for p in paths.get(f.id, []):
            title = "shortest path" if p.rank == 0 else f"alternative {p.rank}"
            flags = " (partial)" if p.partial else ""
            steps = "".join(
                f'<li><span class="rule">{_e(s.rule)}</span> {_e(s.text)}'
                + "".join(f'<br><span class="muted">{_e(src)}</span>' for src in s.sources)
                + "</li>"
                for s in p.steps
            )
            assumptions = "".join(f"<li>{_e(a)}</li>" for a in p.assumptions)
            body.append(
                f'<h3>{title}, rung {_e(p.rung)}{flags}</h3><ol class="steps">{steps}</ol>'
                + (f'<p class="muted">Assumes:</p><ul>{assumptions}</ul>' if assumptions else "")
            )
        parts.append(
            f'<details><summary><span class="{_cls(f.verdict)}">{_e(f.verdict.upper())}</span> '
            f"<code>{_e(f.target)}</code> <code>{_e(f.operation)}</code> "
            f'<span class="muted">{_e(f.item_kind)}, {_e(f.coverage)}</span>'
            + (
                f' &rarr; after prove <span class="{_cls(proved[f.id].verdict)}">'
                f"{_e(proved[f.id].verdict.upper())}</span> "
                f'<span class="muted">{_e(proved[f.id].coverage)}</span>'
                if f.id in proved
                else ""
            )
            + "</summary>"
            f"{''.join(body)}</details>"
        )
    return "".join(parts)


def _proof(bundle: EvidenceBundle, signing: dict[str, str] | None) -> str:
    signer = (signing or {}).get("signer", "unknown")
    warning = (signing or {}).get("warning")
    s = bundle.summary
    return (
        '<h2 id="proof">Proof bundle</h2>'
        f"<p>Run <code>{_e(bundle.run_id)}</code>, verified by <code>{_e(bundle.verifier)}</code>,"
        f" signer <code>{_e(signer)}</code>.</p>"
        + (f'<p class="inconclusive">{_e(warning)}</p>' if warning else "")
        + f"<p>{s.passed} pass, {s.critical} critical, {s.still_do_failed} legitimate use failed, "
        f"{s.inconclusive} inconclusive: {_e(EXIT_MEANING.get(s.exit_code, s.exit_code))}. "
        f"{len(bundle.artifacts)} probe artifact(s). This page does not check the signature; "
        "run <code>fns verify &lt;run dir&gt;</code>.</p>"
    )


def _mutation(m: MutationReport) -> str:
    rows = "".join(
        f'<tr><td class="{OUTCOME_CLASS[r.outcome]}">'
        f"{_e(r.outcome)}</td><td><code>{_e(r.id)}</code></td><td>{_e(r.description)}"
        + (
            f'<br><span class="muted">now fails: {_e("; ".join(r.new_failures))}</span>'
            if r.new_failures
            else ""
        )
        + "</td></tr>"
        for r in m.mutants
    )
    survivors = "".join(
        f"<details><summary>Terraform for survivor <code>{_e(r.id)}</code></summary>"
        f"<pre>{_e(r.terraform_diff)}</pre></details>"
        for r in m.mutants
        if r.outcome != "killed" and r.terraform_diff
    )
    hardened = (
        f'<p class="muted">Baseline hardened in the model by removing '
        f"{_e(', '.join(m.hardened_with))}.</p>"
        if m.hardened_with
        else ""
    )
    warn = (
        f'<p class="fail">The baseline already has {m.baseline_failures} failing finding(s); '
        "this score says little.</p>"
        if m.baseline_failures
        else ""
    )
    na = "".join(f"<li>{_e(n.operator)}: {_e(n.reason)}</li>" for n in m.not_applicable)
    return (
        f'<h2 id="mutation">Mutation score {m.killed}/{m.total}</h2>'
        '<p class="muted">Each mutant weakens the defence by one grant, in the model only. '
        "The contract must notice each one. Survivors are contract gaps.</p>"
        + hardened
        + warn
        + f'<div class="wrap"><table><thead><tr><th>outcome</th><th>mutant</th><th>change</th>'
        f"</tr></thead><tbody>{rows}</tbody></table></div>{survivors}"
        + (f'<p class="muted">Not applicable:</p><ul>{na}</ul>' if na else "")
    )


def render_html(inputs: Inputs) -> str:
    problems = check(inputs)
    if problems:
        raise ReportInputError("; ".join(problems))
    c = inputs.contain
    fixture = c.mode == "FIXTURE"
    s = c.summary
    findings = inputs.bundle.findings if inputs.bundle else c.findings
    source = (
        "After `fns prove` (the bundle's verdicts)"
        if inputs.bundle
        else "From `fns contain` (modeled only)"
    )
    verdict = inputs.bundle.summary.exit_code if inputs.bundle else s.exit_code
    # With a bundle, every count comes from it; the budgets come from the contract.
    b = inputs.bundle.summary if inputs.bundle else None
    critical = b.critical if b else s.critical
    still = b.still_do_failed if b else s.still_do_failed
    inconclusive = b.inconclusive if b else s.inconclusive
    cards = [
        (EXIT_MEANING.get(verdict, str(verdict)), "result", "fail" if verdict else "pass"),
        (
            f"{critical} / {s.max_critical_reachable}",
            "critical reachable / allowed",
            "fail" if critical > s.max_critical_reachable else "",
        ),
        (str(still), "legitimate use failed", "fail" if still else ""),
        (
            f"{inconclusive} / {s.max_inconclusive}",
            "inconclusive / allowed",
            "inconclusive" if inconclusive else "",
        ),
    ]
    if b:
        cards.append((str(b.passed), "passed with evidence", "pass" if b.passed else ""))
    if inputs.mutation:
        m = inputs.mutation
        cards.append(
            (m.score, "mutation score", "pass" if m.killed == m.total and m.total else "fail")
        )
    if inputs.bundle:
        signing = inputs.signing or {}
        signer = signing.get("signer", "unknown")
        if signer == "sigstore" and signing.get("sigstore_instance") == "staging":
            signer = "sigstore staging"
        cards.append((signer, "bundle signer", "inconclusive" if signer != "sigstore" else ""))
    card_html = "".join(
        f'<div class="card"><b class="{cls}">{_e(v)}</b><span>{_e(label)}</span></div>'
        for v, label, cls in cards
    )
    title = f"{'FIXTURE · ' if fixture else ''}{c.contract} · Fang & Scale"
    ladder = "".join(f"<li><b>{_e(r)}</b>: {_e(d)}</li>" for r, d in RUNGS)
    body = [
        '<header><span class="mark">FANG &amp; SCALE</span><span class="tag">Prove what the '
        "bite can't reach.</span></header>",
        '<div class="fixture">FIXTURE: replayed from recorded or hand-written files, not a live '
        "tenant.</div>"
        if fixture
        else "",
        f'<h1>{_e(c.contract)}</h1><p class="muted">Assumed compromised: '
        f"<code>{_e(c.compromised_name or c.compromised or 'unresolved')}</code></p>",
        f'<div class="cards">{card_html}</div>',
        f'<p class="inconclusive">{_e(s.warning)}</p>' if s.warning else "",
        _coverage(findings, source),
        '<h2 id="graph-h">Reach graph</h2><p class="muted">Shortest path to each finding, from '
        "the compromised identity. Red-ringed nodes are escalation steps; diamonds are the "
        "final way in. Select a node to read it.</p>"
        '<div id="graph"></div><div id="graph-detail" class="muted"></div>',
        _findings(c, {f.id: f for f in inputs.bundle.findings} if inputs.bundle else {}),
        _proof(inputs.bundle, inputs.signing) if inputs.bundle else "",
        _mutation(inputs.mutation) if inputs.mutation else "",
        f"<footer><h3>Evidence ladder</h3><ol>{ladder}</ol><p>Contract digest "
        f"<code>{_e(c.contract_digest)}</code><br>Snapshot digest <code>{_e(c.snapshot_digest)}"
        f"</code><br>Report digest <code>{_e(c.digest())}</code><br>Semantics v"
        f"{c.semantics_version}, fns {_e(c.tool_version)}, "
        f"generated {_e(c.generated_at.isoformat())}"
        "</p><p>Read-only page built from files. It makes no network request: Cytoscape "
        f"{CYTOSCAPE_VERSION} (MIT licence, The Cytoscape Consortium) is embedded.</p></footer>",
    ]
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{_csp()}">'
        f"<title>{_e(title)}</title><style>{CSS}</style></head><body><main>"
        + "".join(body)
        + "</main>"
        f'<script type="application/json" id="fns-graph">{_safe_json(graph_elements(c))}</script>'
        f"<script>{cytoscape_js()}</script>"
        f"<script>{SCRIPT}</script></body></html>\n"
    )
