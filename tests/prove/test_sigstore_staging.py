"""V3: Sigstore staging only, production refused until the owner approves it.

Offline: Sigstore is never contacted. The sigstore modules are replaced by fakes
that record which instance was asked for, and the workflow is checked as YAML.
"""

from __future__ import annotations

import base64
import html
import json
import re
import types
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from fns.contain_run import contain, demo_contract
from fns.demo import run_demo_scout
from fns.models.bundle import DSSE_PAYLOAD_TYPE, EvidenceBundle
from fns.probes.mock import MockProbe, load_results
from fns.prove.run import prove
from fns.report.html import Inputs, render_html
from fns.report.markdown import render_comment
from fns.verify import signing
from fns.verify.signing import (
    INSTANCE_ENV,
    PRODUCTION_APPROVED,
    STAGING_WARNING,
    SignatureError,
    sign,
    sigstore_instance,
    verify_envelope,
)

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "prove-sign.yml"
REPO = "danielguillaumont/fang-and-scale"
ISSUER = "https://token.actions.githubusercontent.com"
IDENTITY = f"https://github.com/{REPO}/.github/workflows/prove-sign.yml@refs/heads/main"
PAYLOAD = b'{"_type":"https://in-toto.io/Statement/v1"}'
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")


# --- the instance switch --------------------------------------------------------


def test_production_is_not_approved() -> None:
    """Flipping this needs the owner's explicit approval (docs/DECISIONS.md, V3)."""
    assert PRODUCTION_APPROVED is False


@pytest.mark.parametrize(
    ("env", "expected"),
    [({}, "staging"), ({INSTANCE_ENV: "staging"}, "staging")],
)
def test_staging_is_the_default(env: dict[str, str], expected: str) -> None:
    assert sigstore_instance(env) == expected


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("production", "needs the owner's explicit approval"),
        ("Production", "unknown"),
        ("prod", "unknown"),
        ("", "unknown"),
        ("staging ", "unknown"),
    ],
)
def test_anything_but_staging_is_refused(value: str, match: str) -> None:
    with pytest.raises(SignatureError, match=match):
        sigstore_instance({INSTANCE_ENV: value})


# --- fake sigstore --------------------------------------------------------------


class FakeSigstore:
    """Stands in for the sigstore modules and records every instance asked for."""

    def __init__(self, verified: bytes = PAYLOAD) -> None:
        self.calls: list[str] = []
        self.verified = verified
        self.policy: tuple[str, str] | None = None
        fake = self

        class Trust:
            @staticmethod
            def staging() -> str:
                fake.calls.append("trust:staging")
                return "staging-trust"

            @staticmethod
            def production() -> str:
                fake.calls.append("trust:production")
                return "production-trust"

        class Bundle:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload

            def to_json(self) -> str:
                env: dict[str, Any] = {"payload": base64.b64encode(self.payload).decode()}
                env |= {"payloadType": DSSE_PAYLOAD_TYPE, "signatures": [{"sig": "eA=="}]}
                return json.dumps({"dsseEnvelope": env})

            @staticmethod
            def from_json(text: str) -> str:
                return text

        class Signer:
            def __enter__(self) -> Signer:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def sign_dsse(self, statement: bytes) -> Bundle:
                return Bundle(statement)

        class Context:
            @staticmethod
            def from_trust_config(trust: str) -> Context:
                fake.calls.append(f"context:{trust}")
                return Context()

            def signer(self, token: object) -> Signer:
                return Signer()

        class Verifier:
            @staticmethod
            def staging() -> Verifier:
                fake.calls.append("verifier:staging")
                return Verifier()

            @staticmethod
            def production() -> Verifier:
                fake.calls.append("verifier:production")
                return Verifier()

            def verify_dsse(self, bundle: str, policy: tuple[str, str]) -> tuple[str, bytes]:
                fake.policy = policy
                return DSSE_PAYLOAD_TYPE, fake.verified

        self.modules = {
            "sigstore.sign": types.SimpleNamespace(SigningContext=Context),
            "sigstore.models": types.SimpleNamespace(ClientTrustConfig=Trust, Bundle=Bundle),
            "sigstore.oidc": types.SimpleNamespace(
                IdentityToken=lambda raw: raw, detect_credential=lambda: "oidc-token"
            ),
            "sigstore.dsse": types.SimpleNamespace(Statement=lambda payload: payload),
            "sigstore.verify": types.SimpleNamespace(Verifier=Verifier),
            "sigstore.verify.policy": types.SimpleNamespace(
                Identity=lambda identity, issuer: (identity, issuer)
            ),
        }

    def load(self, module: str) -> Any:
        self.calls.append(f"import:{module}")
        return self.modules[module]


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeSigstore:
    f = FakeSigstore()
    monkeypatch.setattr(signing, "_sigstore", f.load)
    monkeypatch.delenv(INSTANCE_ENV, raising=False)
    return f


def test_signing_uses_staging_and_says_so(fake: FakeSigstore) -> None:
    signed = sign(PAYLOAD, "sigstore")
    assert "trust:staging" in fake.calls
    assert "context:staging-trust" in fake.calls
    assert not [c for c in fake.calls if "production" in c]
    assert signed.signing["sigstore_instance"] == "staging"
    assert signed.signing["warning"] == STAGING_WARNING
    assert base64.b64decode(signed.envelope["payload"]) == PAYLOAD


def test_production_signing_is_refused_before_sigstore_is_imported(
    fake: FakeSigstore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(INSTANCE_ENV, "production")
    with pytest.raises(SignatureError, match="explicit approval"):
        sign(PAYLOAD, "sigstore")
    assert fake.calls == []


def _signed(fake: FakeSigstore) -> tuple[dict[str, Any], dict[str, Any]]:
    signed = sign(PAYLOAD, "sigstore")
    fake.calls.clear()
    return signed.envelope, signed.signing


def test_verification_uses_staging_and_the_given_identity(fake: FakeSigstore) -> None:
    envelope, sig = _signed(fake)
    out = verify_envelope(envelope, sig, sigstore_identity=IDENTITY, sigstore_issuer=ISSUER)
    assert out == PAYLOAD
    assert "verifier:staging" in fake.calls
    assert not [c for c in fake.calls if "production" in c]
    assert fake.policy == (IDENTITY, ISSUER)


@pytest.mark.parametrize(
    ("recorded", "env", "match"),
    [
        ("production", None, "signed on Sigstore production; this verifier is set to staging"),
        (None, None, "signed on Sigstore unknown"),
        ("staging", "production", "explicit approval"),
        ("production", "production", "explicit approval"),
    ],
)
def test_verification_refuses_before_sigstore_is_imported(
    fake: FakeSigstore,
    monkeypatch: pytest.MonkeyPatch,
    recorded: str | None,
    env: str | None,
    match: str,
) -> None:
    envelope, sig = _signed(fake)
    sig = {k: v for k, v in sig.items() if k != "sigstore_instance"}
    if recorded is not None:
        sig["sigstore_instance"] = recorded
    if env is not None:
        monkeypatch.setenv(INSTANCE_ENV, env)
    with pytest.raises(SignatureError, match=match):
        verify_envelope(envelope, sig, sigstore_identity=IDENTITY, sigstore_issuer=ISSUER)
    assert fake.calls == []


def test_verification_needs_identity_and_issuer(fake: FakeSigstore) -> None:
    envelope, sig = _signed(fake)
    with pytest.raises(SignatureError, match="--identity and --issuer"):
        verify_envelope(envelope, sig, sigstore_identity=IDENTITY)
    assert fake.calls == []


def test_a_payload_sigstore_did_not_sign_is_refused(fake: FakeSigstore) -> None:
    envelope, sig = _signed(fake)
    fake.verified = b"something else"
    with pytest.raises(SignatureError, match="differs from the envelope"):
        verify_envelope(envelope, sig, sigstore_identity=IDENTITY, sigstore_issuer=ISSUER)


# --- reports never present a staging bundle as trusted ----------------------------


@pytest.fixture(scope="module")
def proved(tmp_path_factory: pytest.TempPathFactory) -> Inputs:
    run = ROOT / "fixtures" / "lab-run-2"
    tmp = tmp_path_factory.mktemp("staging")
    snap = run_demo_scout(tmp / "scout", run).snapshot
    probe = MockProbe(load_results(run / "probes.json"), at=snap.collected_at)
    done = prove(
        demo_contract(run),
        snap,
        probe,
        tmp / "out",
        now=lambda: datetime(2026, 11, 26, tzinfo=UTC),
        signer="offline-test",
    )
    bundle = EvidenceBundle.model_validate_json((done.run_dir / "bundle.json").read_bytes())
    report = contain(demo_contract(run), snap, now=bundle.generated_at)
    staging = {"signer": "sigstore", "sigstore_instance": "staging", "warning": STAGING_WARNING}
    return Inputs(report, bundle=bundle, signing=staging)


def test_reports_label_a_staging_bundle(proved: Inputs) -> None:
    comment = render_comment(proved)
    assert "bundle signed (Sigstore STAGING)" in comment
    assert "bundle signed (Sigstore)" not in comment
    page = render_html(proved)
    assert "sigstore staging" in page
    assert html.escape(STAGING_WARNING) in page


# --- the workflow -------------------------------------------------------------------


def _load(path: Path) -> dict[Any, Any]:
    doc: dict[Any, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return doc


def _triggers(doc: dict[Any, Any]) -> dict[str, Any]:
    on = doc.get("on", doc.get(True))  # YAML 1.1 reads a bare `on` key as True
    assert isinstance(on, dict)
    return on


def test_workflow_runs_only_on_main_and_by_hand() -> None:
    doc = _load(WORKFLOW)
    on = _triggers(doc)
    assert set(on) == {"push", "workflow_dispatch"}
    assert on["push"] == {"branches": ["main"]}
    (job,) = doc["jobs"].values()
    assert job["if"] == "github.ref == 'refs/heads/main'"


def test_id_token_is_granted_on_one_job_only() -> None:
    doc = _load(WORKFLOW)
    assert doc["permissions"] == {}
    (job,) = doc["jobs"].values()
    assert job["permissions"] == {"contents": "read", "id-token": "write"}


@pytest.mark.parametrize("path", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_no_other_workflow_can_mint_an_oidc_token(path: Path) -> None:
    doc = _load(path)
    perms = [doc.get("permissions") or {}]
    perms += [j.get("permissions") or {} for j in doc["jobs"].values()]
    grants = [p for p in perms if isinstance(p, dict) and p.get("id-token") == "write"]
    if path != WORKFLOW:
        assert grants == [], path.name
    on = _triggers(doc)
    if grants:
        assert not {"pull_request", "pull_request_target", "workflow_run"} & set(on)


def test_the_signing_identity_is_this_workflow_on_main() -> None:
    doc = _load(WORKFLOW)
    (job,) = doc["jobs"].values()
    rel = WORKFLOW.relative_to(ROOT).as_posix()
    assert job["env"]["SIGSTORE_IDENTITY"] == f"https://github.com/{REPO}/{rel}@refs/heads/main"
    assert job["env"]["SIGSTORE_IDENTITY"] == IDENTITY
    assert job["env"]["SIGSTORE_ISSUER"] == ISSUER


def test_workflow_is_staging_only_and_pinned() -> None:
    doc = _load(WORKFLOW)
    (job,) = doc["jobs"].values()
    assert job["env"][INSTANCE_ENV] == "staging"
    steps = job["steps"]
    for step in steps:
        if "uses" in step:
            assert SHA_PIN.match(step["uses"]), step["uses"]
        assert INSTANCE_ENV not in (step.get("env") or {}), "only the job sets the instance"
        assert "production" not in (step.get("run") or "").lower()
    runs = "\n".join(s.get("run", "") for s in steps)
    assert "uv sync --locked --no-dev --extra sigstore" in runs
    assert "--sign sigstore" in runs
    assert "fns.verify check" in runs
    assert "--sigstore-identity" in runs and "--sigstore-issuer" in runs
    assert "az " not in runs and "azure/login" not in json.dumps(steps)
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False


def test_workflow_signs_the_recorded_fixture_not_a_live_run() -> None:
    doc = _load(WORKFLOW)
    (job,) = doc["jobs"].values()
    fixture = ROOT / job["env"]["FIXTURE"]
    assert (fixture / "probes.json").is_file()
    assert (fixture / "contract.fns.yaml").is_file()
    runs = "\n".join(s.get("run", "") for s in job["steps"])
    assert "--live" not in runs
    assert "fns demo scout --fixture" in runs
