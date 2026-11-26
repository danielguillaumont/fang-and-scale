"""M3 regression test: the M3 live run (2026-11-26) recorded as ``fixtures/lab-run-3``.

The scout half was recorded by ``fns scout --record`` as ``sp-fns-scout``; the probe
half by ``fns prove --live --record`` as ``sp-billing-agent``, the identity the
contract assumes is compromised. The live run gave:

- scout digest ``sha256:68a0208d...b129`` (identical to M2), 34 gated calls;
- ``fns prove --live``: passed 1, critical reachable 11, still-do failed 0,
  inconclusive 1, exit 1. Invoices ``blob/read`` passed (observed, verified). The
  Key Vault ``secrets/get`` and ``secrets/list`` and payroll ``blob/read`` reads
  were denied when probed and still fail: escalation paths remain;
- live bundle ``sha256:4b537ab6...``; this replay's bundle ``sha256:ab673d8e...``.

The two bundle digests differ by design (``docs/FINDINGS.md``, "Live and replay
bundle digests differ"): IDs are placeholders here, probe IDs hash the target's
full ARM path, the mode is FIXTURE, and run IDs and timestamps differ. Verdicts,
coverage and evidence rungs are identical, and this test pins them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fns.contain_run import demo_contract
from fns.demo import run_demo_scout
from fns.models.bundle import EvidenceBundle
from fns.probes.mock import MockProbe, load_results
from fns.prove.run import ProveResult, prove
from fns.summary import ScoutResult

ROOT = Path(__file__).resolve().parents[2]
LAB_RUN = ROOT / "fixtures" / "lab-run-3"
GOLDEN = ROOT / "tests" / "golden"


def _golden(name: str) -> str:
    return (GOLDEN / f"{name}.digest").read_text(encoding="utf-8").strip()


@pytest.fixture(scope="module")
def scout(tmp_path_factory: pytest.TempPathFactory) -> ScoutResult:
    return run_demo_scout(tmp_path_factory.mktemp("lab3"), LAB_RUN)


@pytest.fixture(scope="module")
def proved(scout: ScoutResult, tmp_path_factory: pytest.TempPathFactory) -> ProveResult:
    snap = scout.snapshot
    probe = MockProbe(load_results(LAB_RUN / "probes.json"), at=snap.collected_at)
    return prove(
        demo_contract(LAB_RUN),
        snap,
        probe,
        tmp_path_factory.mktemp("prove3"),
        now=lambda: snap.collected_at,
        signer="offline-test",
        identity="fixture-replay",
    )


@pytest.fixture(scope="module")
def bundle(proved: ProveResult) -> EvidenceBundle:
    return EvidenceBundle.model_validate_json((proved.run_dir / "bundle.json").read_bytes())


def test_scout_half_is_the_m2_snapshot(scout: ScoutResult) -> None:
    """The lab did not change between M2 and M3: same replay digest, same counts."""
    assert scout.digest == _golden("lab-run-3") == _golden("lab-run-2")
    snap = scout.snapshot
    assert snap.mode == "FIXTURE"
    assert (len(snap.entities), len(snap.edges), scout.calls) == (211, 32, 34)


RECORDED = {
    ("arm-permissions", "kv-crown-tiin02", "getSecret/action"): ("denied", 200),
    ("arm-permissions", "kv-crown-tiin02", "readMetadata/action"): ("denied", 200),
    ("arm-permissions", "kv-crown-tiin02", "vaults/write"): ("allowed", 200),
    ("arm-permissions", "stinvoicestiin02", "add/action"): ("allowed", 200),
    ("arm-permissions", "stinvoicestiin02", "blobs/read"): ("allowed", 200),
    ("arm-permissions", "stinvoicestiin02", "blobs/write"): ("allowed", 200),
    ("arm-permissions", "stinvoicestiin02", "listKeys/action"): ("allowed", 200),
    ("arm-permissions", "stpayrolltiin02", "blobs/read"): ("denied", 200),
    ("arm-permissions", "stpayrolltiin02", "listKeys/action"): ("allowed", 200),
    ("data-read", "kv-crown-tiin02", "secrets/get"): ("denied", 403),
    ("data-read", "kv-crown-tiin02", "secrets/list"): ("denied", 403),
    ("data-read", "stinvoicestiin02", "blob/read"): ("allowed", 200),
    ("data-read", "stpayrolltiin02", "blob/read"): ("denied", 403),
}


def test_probe_results_are_the_sanitized_live_recording() -> None:
    doc = json.loads((LAB_RUN / "probes.json").read_text(encoding="utf-8"))
    assert doc["label"] == "FIXTURE"
    assert doc["description"].startswith("Recorded from the lab by fns prove --live on 2026-11-26")
    got = {
        (r["kind"], r["resource"], "/".join(r["action"].split("/")[-2:])): (
            r["outcome"],
            r["http_status"],
        )
        for r in doc["results"]
    }
    assert got == RECORDED
    details = {r["action"]: r["detail"] for r in doc["results"] if r["kind"] == "data-read"}
    assert details["secrets/get"] == "HTTP 403 Forbidden/ForbiddenByRbac (authorization denied)"
    assert details["secrets/list"] == "HTTP 403 Forbidden/ForbiddenByRbac (authorization denied)"
    blob = {r["resource"]: r["detail"] for r in doc["results"] if r["action"] == "blob/read"}
    assert (
        blob["stpayrolltiin02"] == "HTTP 403 AuthorizationPermissionMismatch (authorization denied)"
    )
    assert blob["stinvoicestiin02"] == "HTTP 200"
    # Sanitized: no request IDs, no principals, no bodies (decision V6).
    for r in doc["results"]:
        assert set(r) == {"action", "detail", "http_status", "kind", "outcome", "resource"}


EXPECTED = {
    ("resource:kv-crown-tiin02", "secrets/get"): ("fail", "evaluated-only"),
    ("resource:kv-crown-tiin02", "secrets/list"): ("fail", "evaluated-only"),
    ("resource:stpayrolltiin02", "blob/read"): ("fail", "evaluated-only"),
    ("resource:stpayrolltiin02", "listKeys"): ("fail", "evaluated-only"),
    ("resource:stinvoicestiin02", "listKeys"): ("fail", "evaluated-only"),
    ("directory:tenant", "roleAssignments/write"): ("fail", "modeled-only"),
    ("directory:tenant", "applications/credentials/update"): ("fail", "modeled-only"),
    ("application:id-verifier", "credentials/update"): ("fail", "modeled-only"),
    ("application:id-verifier", "owners/update"): ("fail", "modeled-only"),
    ("application:sp-fns-scout", "credentials/update"): ("fail", "modeled-only"),
    ("application:sp-fns-scout", "owners/update"): ("fail", "modeled-only"),
    ("resource:stinvoicestiin02", "blob/read"): ("pass", "verified"),
    ("resource:stinvoicestiin02", "blob/write"): ("inconclusive", "evaluated-only"),
}


def test_prove_verdicts_match_the_live_run(proved: ProveResult, bundle: EvidenceBundle) -> None:
    got = {(f.target, f.operation): (f.verdict, f.coverage) for f in bundle.findings}
    assert got == EXPECTED
    s = bundle.summary
    assert (s.passed, s.critical, s.still_do_failed, s.inconclusive, s.exit_code) == (
        1,
        11,
        0,
        1,
        1,
    )
    assert proved.exit_code == 1
    assert bundle.mode == "FIXTURE"


EXPECTED_PASS = ("resource:stinvoicestiin02", "blob/read")


def test_the_one_pass_is_observed(bundle: EvidenceBundle) -> None:
    """M3's gate: a verdict backed by an observed probe, not only the model."""
    f = next(f for f in bundle.findings if (f.target, f.operation) == EXPECTED_PASS)
    assert "observed" in {e.rung for e in f.evidence}
    observed = [e for e in f.evidence if e.rung == "observed"]
    assert {e.outcome for e in observed} == {"allowed"}


@pytest.mark.parametrize(
    "item",
    [
        ("resource:kv-crown-tiin02", "secrets/get"),
        ("resource:kv-crown-tiin02", "secrets/list"),
        ("resource:stpayrolltiin02", "blob/read"),
    ],
)
def test_denied_when_probed_but_still_failing(
    bundle: EvidenceBundle, item: tuple[str, str]
) -> None:
    """The direct read was denied when probed, but an escalation hop is listed.

    The denial itself is in RECORDED (and the bundle's artifacts); the finding's
    evidence holds the allowed hop that keeps it failing. Linking the denial to the
    finding too is an open verifier question (docs/STATUS.md).
    """
    f = next(f for f in bundle.findings if (f.target, f.operation) == item)
    assert f.verdict == "fail"
    assert "the operation itself was denied when probed, but escalation paths remain" in f.reasons
    assert any(e.rung == "evaluated" and e.outcome == "allowed" for e in f.evidence)


def test_replay_bundle_digest_is_pinned(bundle: EvidenceBundle) -> None:
    assert bundle.digest() == _golden("lab-run-3-prove")
