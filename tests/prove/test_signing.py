"""DSSE / in-toto signing in offline test mode."""

from __future__ import annotations

import base64
import importlib.util
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fns.models.bundle import DSSE_PAYLOAD_TYPE
from fns.verify.signing import (
    TEST_WARNING,
    SignatureError,
    pae,
    sign,
    sign_offline,
    unsigned,
    verify_envelope,
)

PAYLOAD = b'{"_type":"https://in-toto.io/Statement/v1"}'


def test_pae_matches_the_dsse_spec_example() -> None:
    assert (
        pae("http://example.com/HelloWorld", b"hello world")
        == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


def test_sign_and_verify_round_trip() -> None:
    signed = sign(PAYLOAD, "offline-test")
    assert signed.envelope["payloadType"] == DSSE_PAYLOAD_TYPE
    assert signed.signing["warning"] == TEST_WARNING
    assert verify_envelope(signed.envelope, signed.signing) == PAYLOAD


def test_same_key_signs_deterministically() -> None:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    assert sign_offline(PAYLOAD, key).envelope == sign_offline(PAYLOAD, key).envelope


def _flip(b64: str) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[len(raw) // 2] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


@pytest.mark.parametrize("field", ["payload", "sig", "keyid", "public_key", "payloadType"])
def test_any_change_fails_verification(field: str) -> None:
    signed = sign_offline(PAYLOAD)
    env: dict[str, Any] = json.loads(json.dumps(signed.envelope))
    signing: dict[str, Any] = dict(signed.signing)
    if field == "payload":
        env["payload"] = _flip(env["payload"])
    elif field == "sig":
        env["signatures"][0]["sig"] = _flip(env["signatures"][0]["sig"])
    elif field == "keyid":
        env["signatures"][0]["keyid"] = "offline-test:0000000000000000"
    elif field == "public_key":
        other = sign_offline(PAYLOAD)
        signing["public_key"] = other.signing["public_key"]
    else:
        env["payloadType"] = "application/json"
    with pytest.raises(SignatureError):
        verify_envelope(env, signing)


def test_unsigned_and_unknown_signers_never_verify() -> None:
    u = unsigned(PAYLOAD)
    with pytest.raises(SignatureError, match="unsigned"):
        verify_envelope(u.envelope, u.signing)
    with pytest.raises(SignatureError, match="unknown signer"):
        verify_envelope(u.envelope, {"signer": "trust-me"})


def test_sigstore_without_the_extra_says_how_to_get_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """Runs whether or not the extra is installed: the import failure is simulated."""
    real = importlib.import_module

    def no_sigstore(name: str, package: str | None = None) -> object:
        if name.split(".")[0] == "sigstore":
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real(name, package)

    monkeypatch.setattr(importlib, "import_module", no_sigstore)
    monkeypatch.delenv("FNS_SIGSTORE_INSTANCE", raising=False)
    with pytest.raises(SignatureError, match="optional extra: uv sync --extra sigstore"):
        sign(PAYLOAD, "sigstore")


def test_the_sigstore_api_we_call_exists() -> None:
    """Offline: the pinned sigstore has every name sign_sigstore and verify_envelope use.

    Nothing is constructed (staging() would fetch the trust root). Skips only
    without the extra; poe setup and CI install it (pyproject.toml).
    """
    pytest.importorskip("sigstore", reason="needs the sigstore extra: uv run poe setup")
    sign_mod, models, oidc, dsse, verify, policy, errors = (
        importlib.import_module(m)
        for m in (
            "sigstore.sign",
            "sigstore.models",
            "sigstore.oidc",
            "sigstore.dsse",
            "sigstore.verify",
            "sigstore.verify.policy",
            "sigstore.errors",
        )
    )
    # signing.py turns these into SignatureError (exit 5): they must share one base.
    assert issubclass(errors.VerificationError, errors.Error)
    assert issubclass(models.InvalidBundle, errors.Error)
    assert issubclass(oidc.IdentityError, errors.Error)
    assert callable(models.ClientTrustConfig.staging)
    assert callable(models.ClientTrustConfig.production)
    assert callable(models.Bundle.from_json)
    assert callable(sign_mod.SigningContext.from_trust_config)
    assert callable(oidc.IdentityToken) and callable(oidc.detect_credential)
    assert callable(dsse.Statement)
    assert callable(verify.Verifier.staging) and callable(verify.Verifier.production)
    assert callable(verify.Verifier.verify_dsse)
    assert callable(policy.Identity)
