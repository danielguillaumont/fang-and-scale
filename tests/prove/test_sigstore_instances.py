"""V3: Sigstore production signs only from prove-sign.yml on a push to main.

Staging is the default everywhere else. Verification works on either instance,
anywhere, against the instance the verifier is told to use.

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
from fns.prove.run import prove, verifier_env
from fns.report.html import Inputs, render_html
from fns.report.markdown import render_comment
from fns.verify import main as verifier
from fns.verify import signing
from fns.verify.signing import (
    INSTANCE_ENV,
    PRODUCTION_REPOSITORY,
    PRODUCTION_WORKFLOW_REF,
    STAGING_WARNING,
    SignatureError,
    check_production_origin,
    sign,
    sign_sigstore,
    sigstore_instance,
    verify_envelope,
)

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "prove-sign.yml"
REPO = "danielguillaumont/fang-and-scale"
ISSUER = "https://token.actions.githubusercontent.com"
IDENTITY = f"https://github.com/{REPO}/.github/workflows/prove-sign.yml@refs/heads/main"
T = datetime(2026, 11, 26, tzinfo=UTC)
PAYLOAD = b'{"_type":"https://in-toto.io/Statement/v1"}'
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
MAIN_PUSH = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_REPOSITORY": REPO,
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/prove-sign.yml@refs/heads/main",
}


# --- the instance switch --------------------------------------------------------


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, "staging"),
        ({INSTANCE_ENV: "staging"}, "staging"),
        ({INSTANCE_ENV: "production"}, "production"),
    ],
)
def test_staging_is_the_default(env: dict[str, str], expected: str) -> None:
    assert sigstore_instance(env) == expected


@pytest.mark.parametrize("value", ["Production", "prod", "", "staging ", "public-good"])
def test_unknown_instances_are_refused(value: str) -> None:
    with pytest.raises(SignatureError, match="unknown"):
        sigstore_instance({INSTANCE_ENV: value})


def test_the_production_origin_is_this_repository_and_workflow() -> None:
    assert PRODUCTION_REPOSITORY == REPO
    assert f"https://github.com/{PRODUCTION_WORKFLOW_REF}" == IDENTITY
    rel = WORKFLOW.relative_to(ROOT).as_posix()
    assert f"{REPO}/{rel}@refs/heads/main" == PRODUCTION_WORKFLOW_REF
    check_production_origin(MAIN_PUSH)  # does not raise


def test_the_origin_variables_reach_the_verifier_process() -> None:
    """The verifier signs in its own process; its scrubbed environment keeps them."""
    assert verifier_env(MAIN_PUSH) == MAIN_PUSH


# --- fake sigstore --------------------------------------------------------------


class FakeSigstore:
    """Stands in for the sigstore modules and records every instance asked for."""

    def __init__(self, verified: bytes | None = None) -> None:
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
                if fake.verified is not None:
                    return DSSE_PAYLOAD_TYPE, fake.verified
                signed = json.loads(bundle)["dsseEnvelope"]["payload"]
                return DSSE_PAYLOAD_TYPE, base64.b64decode(signed)

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
    for name in MAIN_PUSH:
        monkeypatch.delenv(name, raising=False)
    return f


def test_signing_uses_staging_and_says_so(fake: FakeSigstore) -> None:
    signed = sign(PAYLOAD, "sigstore")
    assert "trust:staging" in fake.calls
    assert "context:staging-trust" in fake.calls
    assert not [c for c in fake.calls if "production" in c]
    assert signed.signing["sigstore_instance"] == "staging"
    assert signed.signing["warning"] == STAGING_WARNING
    assert base64.b64decode(signed.envelope["payload"]) == PAYLOAD


def test_production_signs_from_a_push_to_main(
    fake: FakeSigstore, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name, value in {**MAIN_PUSH, INSTANCE_ENV: "production"}.items():
        monkeypatch.setenv(name, value)
    signed = sign(PAYLOAD, "sigstore")
    assert "context:production-trust" in fake.calls
    assert not [c for c in fake.calls if "staging" in c]
    assert signed.signing["sigstore_instance"] == "production"
    assert "warning" not in signed.signing


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GITHUB_ACTIONS", None),  # a local run
        ("GITHUB_REPOSITORY", "someone/fang-and-scale"),  # a fork
        ("GITHUB_REPOSITORY", None),
        ("GITHUB_REF", "refs/pull/7/merge"),  # a pull request
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_REF", "refs/tags/m3"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_EVENT_NAME", "pull_request_target"),
        ("GITHUB_WORKFLOW_REF", f"{REPO}/.github/workflows/ci.yml@refs/heads/main"),
        ("GITHUB_WORKFLOW_REF", f"{REPO}/.github/workflows/prove-sign.yml@refs/heads/dev"),
    ],
)
def test_production_is_refused_anywhere_else_before_sigstore_is_imported(
    fake: FakeSigstore, name: str, value: str | None
) -> None:
    env = {**MAIN_PUSH, INSTANCE_ENV: "production"}
    if value is None:
        del env[name]
    else:
        env[name] = value
    with pytest.raises(SignatureError, match=f"not here: {name}"):
        sign_sigstore(PAYLOAD, env=env)
    with pytest.raises(SignatureError, match=name):
        sign_sigstore(PAYLOAD, "production", env=env)
    assert fake.calls == []


def test_production_is_refused_from_a_developer_machine(
    fake: FakeSigstore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(INSTANCE_ENV, "production")
    with pytest.raises(SignatureError, match=r"only from prove-sign.yml on a push to main"):
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


@pytest.mark.parametrize("how", ["argument", "environment"])
def test_anyone_can_verify_a_production_bundle(
    fake: FakeSigstore, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    """No GitHub variables here: the origin check guards signing, not verifying."""
    envelope, sig = _signed(fake)
    sig["sigstore_instance"] = "production"
    if how == "environment":
        monkeypatch.setenv(INSTANCE_ENV, "production")
    instance: Any = "production" if how == "argument" else None
    out = verify_envelope(
        envelope, sig, sigstore_identity=IDENTITY, sigstore_issuer=ISSUER, instance=instance
    )
    assert out == PAYLOAD
    assert "verifier:production" in fake.calls
    assert not [c for c in fake.calls if "staging" in c]


@pytest.mark.parametrize(
    ("recorded", "env", "instance", "match"),
    [
        ("production", None, None, "Sigstore production; this verifier is set to staging"),
        (None, None, None, "signed on Sigstore unknown"),
        ("staging", "production", None, "Sigstore staging; this verifier is set to production"),
        ("staging", None, "production", "this verifier is set to production"),
        ("production", "production", "staging", "this verifier is set to staging"),
        ("production", "prod", None, "unknown"),
    ],
)
def test_verification_refuses_before_sigstore_is_imported(
    fake: FakeSigstore,
    monkeypatch: pytest.MonkeyPatch,
    recorded: str | None,
    env: str | None,
    instance: Any,
    match: str,
) -> None:
    envelope, sig = _signed(fake)
    sig = {k: v for k, v in sig.items() if k != "sigstore_instance"}
    if recorded is not None:
        sig["sigstore_instance"] = recorded
    if env is not None:
        monkeypatch.setenv(INSTANCE_ENV, env)
    with pytest.raises(SignatureError, match=match):
        verify_envelope(
            envelope, sig, sigstore_identity=IDENTITY, sigstore_issuer=ISSUER, instance=instance
        )
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


def test_reports_do_not_call_a_production_bundle_staging(proved: Inputs) -> None:
    prod = Inputs(
        proved.contain,
        bundle=proved.bundle,
        signing={"signer": "sigstore", "sigstore_instance": "production"},
    )
    comment = render_comment(prod)
    assert "bundle signed (Sigstore)" in comment
    assert "STAGING" not in comment
    assert "staging" not in render_html(prod).lower()


# --- the run directory ------------------------------------------------------------


@pytest.fixture
def sigstore_run(fake: FakeSigstore, tmp_path: Path) -> Path:
    """A real run directory, re-signed in-process by the fake Sigstore."""
    run = ROOT / "fixtures" / "lab-run-2"
    snap = run_demo_scout(tmp_path / "scout", run).snapshot
    probe = MockProbe(load_results(run / "probes.json"), at=snap.collected_at)
    out = tmp_path / "out"
    done = prove(demo_contract(run), snap, probe, out, now=lambda: T, signer="none")
    code = verifier.run(done.run_dir, signer="sigstore", identity="test", echo=lambda _: None)
    assert code == 1  # the fixture contract fails on purpose
    return done.run_dir


def test_the_sigstore_bundle_is_written_on_its_own_for_other_clients(sigstore_run: Path) -> None:
    standalone = json.loads((sigstore_run / verifier.SIGSTORE_BUNDLE_FILE).read_bytes())
    recorded = json.loads((sigstore_run / verifier.SIGNING_FILE).read_bytes())
    assert standalone == recorded["sigstore_bundle"]
    stmt = json.loads((sigstore_run / verifier.STATEMENT_FILE).read_bytes())
    assert "assertions.json" in {s["name"] for s in stmt["subject"]}  # the README's subject
    lines: list[str] = []
    ok = verifier.check(
        sigstore_run, echo=lines.append, sigstore_identity=IDENTITY, sigstore_issuer=ISSUER
    )
    assert ok == 0, lines


def test_check_refuses_a_standalone_bundle_that_differs(sigstore_run: Path) -> None:
    path = sigstore_run / verifier.SIGSTORE_BUNDLE_FILE
    doc = json.loads(path.read_bytes())
    doc["dsseEnvelope"]["signatures"] = []
    path.write_text(json.dumps(doc), encoding="utf-8")
    lines: list[str] = []
    bad = verifier.check(
        sigstore_run, echo=lines.append, sigstore_identity=IDENTITY, sigstore_issuer=ISSUER
    )
    assert bad == 5
    assert "bundle.sigstore.json differs from signing.json" in lines[0]


# --- the workflow -------------------------------------------------------------------


def _load(path: Path) -> dict[Any, Any]:
    doc: dict[Any, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return doc


def _triggers(doc: dict[Any, Any]) -> dict[str, Any]:
    on = doc.get("on", doc.get(True))  # YAML 1.1 reads a bare `on` key as True
    assert isinstance(on, dict)
    return on


def test_workflow_runs_on_main_and_on_pull_requests_from_this_repository() -> None:
    doc = _load(WORKFLOW)
    on = _triggers(doc)
    assert set(on) == {"push", "pull_request", "workflow_dispatch"}
    assert on["push"] == {"branches": ["main"]}
    (job,) = doc["jobs"].values()
    condition = " ".join(job["if"].split())
    assert condition == (
        "github.ref == 'refs/heads/main' || (github.event_name == 'pull_request' "
        "&& github.event.pull_request.head.repo.full_name == github.repository "
        "&& github.actor != 'dependabot[bot]')"
    )


def test_workflow_asks_for_production_only_on_a_push_to_main() -> None:
    (job,) = _load(WORKFLOW)["jobs"].values()
    assert job["env"][INSTANCE_ENV] == (
        "${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') "
        "&& 'production' || 'staging' }}"
    )


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
        # Never a trigger that runs fork code with this repository's privileges.
        assert not {"pull_request_target", "workflow_run"} & set(on)


def test_the_signing_identity_is_this_workflow_on_main() -> None:
    doc = _load(WORKFLOW)
    (job,) = doc["jobs"].values()
    rel = WORKFLOW.relative_to(ROOT).as_posix()
    assert f"https://github.com/{REPO}/{rel}@refs/heads/main" == IDENTITY
    # On main the identity is the fixed string; elsewhere it is the run's own ref.
    assert job["env"]["SIGSTORE_IDENTITY"] == (
        f"${{{{ github.ref == 'refs/heads/main' && '{IDENTITY}' "
        "|| format('https://github.com/{0}', github.workflow_ref) }}"
    )
    assert job["env"]["SIGSTORE_ISSUER"] == ISSUER


def test_workflow_verifies_with_both_verifiers_and_is_pinned() -> None:
    doc = _load(WORKFLOW)
    (job,) = doc["jobs"].values()
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
    assert '--sigstore-instance "$FNS_SIGSTORE_INSTANCE"' in runs
    assert "python -m sigstore" in runs and "verify github" in runs
    assert '--bundle "$RUN_DIR/bundle.sigstore.json"' in runs
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


def test_the_prove_step_reads_the_exit_code_before_errexit_can_stop_it() -> None:
    """Steps run under bash -eo pipefail; the expected exit 1 must not end the step.

    Regression: the first run on main signed on staging, then stopped at the
    pipeline's exit 1 before the code check, so the verify step never ran.
    """
    doc = _load(WORKFLOW)
    (job,) = doc["jobs"].values()
    step = next(s for s in job["steps"] if s.get("id") == "prove")
    lines = [ln.strip() for ln in step["run"].splitlines()]
    commands = [ln for ln in lines if ln and not ln.startswith("#")]
    assert commands[0].startswith("set +e"), commands[0]
    read = commands.index("code=${PIPESTATUS[0]}")
    assert commands[read + 1] == "set -e"
    assert not any(c.startswith("set -e") for c in commands[:read])
