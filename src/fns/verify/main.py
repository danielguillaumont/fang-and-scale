"""``python -m fns.verify run|check --run DIR``: the verifier process.

``run`` reads the run directory (frozen assertions, read-only journal, artifacts),
judges every assertion, writes the evidence bundle and its signed statement, and
exits with the contract's exit code. ``check`` re-verifies a finished run: the
signature, every subject digest, and the verdicts (re-derived from the inputs).
Integrity failures exit 5 and produce no bundle.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from fns import __version__
from fns.exitcodes import ExitCode
from fns.models.bundle import ArtifactRef, EvidenceBundle
from fns.models.evidence import Finding
from fns.verify.inputs import ARTIFACTS_DIR, ASSERTIONS_FILE, Inputs, IntegrityError, load_inputs
from fns.verify.signing import SignatureError, SignerName, sign, statement, verify_envelope
from fns.verify.verdict import judge, summarize

BUNDLE_FILE: Final = "bundle.json"
STATEMENT_FILE: Final = "statement.intoto.json"
ENVELOPE_FILE: Final = "bundle.dsse.json"
SIGNING_FILE: Final = "signing.json"

Print = Callable[[str], None]


def _printer(mode: str, echo: Print) -> Print:
    prefix = "FIXTURE " if mode == "FIXTURE" else ""
    return lambda line: echo(f"{prefix}{line}")


def build(inputs: Inputs, *, identity: str, now: datetime) -> tuple[EvidenceBundle, bytes]:
    aset = inputs.assertions
    findings: list[Finding] = []
    for a in aset.assertions:
        obs = {
            pid: o for pid, o in inputs.observations.items() if any(p.id == pid for p in a.probes)
        }
        findings.append(judge(a, obs, aset.contract))
    artifacts = tuple(
        ArtifactRef(sha256=sha, probe_id=pid, finding_id=o.finding_id)
        for pid, (o, sha) in sorted(inputs.observations.items())
    )
    bundle = EvidenceBundle(
        version=1,
        mode=aset.mode,
        run_id=aset.run_id,
        contract=aset.contract,
        tenant_id=aset.tenant_id,
        assertions_digest=inputs.assertions_digest,
        contract_digest=aset.contract_digest,
        snapshot_digest=aset.snapshot_digest,
        report_digest=aset.report_digest,
        verifier=f"fns.verify as {identity}",
        generated_at=now,
        tool_version=__version__,
        findings=tuple(findings),
        artifacts=artifacts,
        summary=summarize(findings, aset.thresholds),
    )
    subjects = {ASSERTIONS_FILE: inputs.assertions_digest}
    subjects.update({f"{ARTIFACTS_DIR}/{a.sha256}.json": a.sha256 for a in artifacts})
    return bundle, statement(bundle, subjects)


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def run(
    run_dir: Path,
    *,
    signer: SignerName,
    identity: str,
    echo: Print = print,
    now: datetime | None = None,
) -> int:
    try:
        inputs = load_inputs(run_dir)
    except IntegrityError as exc:
        echo(f"EVIDENCE INVALID: {exc}")
        return int(ExitCode.EVIDENCE_INVALID)
    out = _printer(inputs.assertions.mode, echo)
    if now is None and inputs.assertions.mode == "FIXTURE":
        now = inputs.assertions.frozen_at  # replay is deterministic
    bundle, payload = build(inputs, identity=identity, now=now or datetime.now(UTC))
    try:
        signed = sign(payload, signer)
    except SignatureError as exc:
        out(f"signing failed: {exc}")
        return int(ExitCode.EVIDENCE_INVALID)
    _write(run_dir / BUNDLE_FILE, (bundle.canonical_json() + "\n").encode("utf-8"))
    _write(run_dir / STATEMENT_FILE, payload)
    _write(run_dir / ENVELOPE_FILE, _json_bytes(signed.envelope))
    _write(run_dir / SIGNING_FILE, _json_bytes(signed.signing))
    render(bundle, signed.signing, out)
    return bundle.summary.exit_code


def render(bundle: EvidenceBundle, signing: dict[str, Any], out: Print) -> None:
    out(f"Verifier: {bundle.verifier} (separate process; reads frozen assertions + journal)")
    out("Findings")
    for f in sorted(bundle.findings, key=lambda f: (f.item_kind, f.target, f.operation)):
        rung = max(
            (e.rung for e in f.supporting if e.outcome in {"allowed", "denied"}),
            key=lambda r: ["modeled", "evaluated", "observed", "logged"].index(r),
            default="none",
        )
        gap = f" [{f.gap}]" if f.gap else ""
        out(f"  {f.verdict.upper():<12} {f.target} {f.operation}  {rung} / {f.coverage}{gap}")
        out(f"      {f.reasons[0]}")
    s = bundle.summary
    out(
        f"passed: {s.passed}  critical reachable: {s.critical}  "
        f"still-do failed: {s.still_do_failed}  inconclusive: {s.inconclusive}"
    )
    out(f"signer: {signing.get('signer')}")
    if signing.get("warning"):
        out(str(signing["warning"]))
    out(f"bundle sha256:{bundle.digest()}")
    if s.exit_code == 0:
        out("WITHIN BUDGET (exit 0)" + (f"; warning: {s.warning}" if s.warning else ""))
    elif s.exit_code == 3:
        out("inconclusive over budget (exit 3)")
    else:
        out("contract FAILED (exit 1)")


def check(
    run_dir: Path,
    *,
    echo: Print = print,
    sigstore_identity: str | None = None,
    sigstore_issuer: str | None = None,
) -> int:
    """Re-verify a finished run. Returns 0 if everything checks out, else 5."""
    try:
        inputs = load_inputs(run_dir)
        envelope = json.loads((run_dir / ENVELOPE_FILE).read_bytes())
        signing = json.loads((run_dir / SIGNING_FILE).read_bytes())
        payload = verify_envelope(
            envelope,
            signing,
            sigstore_identity=sigstore_identity,
            sigstore_issuer=sigstore_issuer,
        )
        if payload != (run_dir / STATEMENT_FILE).read_bytes():
            raise SignatureError("statement file differs from the signed payload")
        stmt = json.loads(payload)
        bundle = EvidenceBundle.model_validate(stmt["predicate"])
        on_disk = EvidenceBundle.model_validate_json((run_dir / BUNDLE_FILE).read_bytes())
        if bundle.canonical_json() != on_disk.canonical_json():
            raise SignatureError("bundle.json differs from the signed predicate")
        for subject in stmt["subject"]:
            data = (run_dir / subject["name"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != subject["digest"]["sha256"]:
                raise SignatureError(f"subject {subject['name']} does not match its digest")
        rebuilt, _ = build(inputs, identity="check", now=bundle.generated_at)
        if [f.canonical_json() for f in rebuilt.findings] != [
            f.canonical_json() for f in bundle.findings
        ]:
            raise SignatureError("verdicts do not follow from the inputs")
    except (IntegrityError, SignatureError, OSError, ValueError, KeyError, ValidationError) as exc:
        echo(f"EVIDENCE INVALID: {exc}")
        return int(ExitCode.EVIDENCE_INVALID)
    out = _printer(bundle.mode, echo)
    out(f"bundle sha256:{bundle.digest()} verified ({signing.get('signer')})")
    if signing.get("warning"):
        out(str(signing["warning"]))
    return 0
