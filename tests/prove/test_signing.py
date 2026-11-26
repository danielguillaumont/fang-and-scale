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


def test_sigstore_without_the_extra_says_how_to_get_it() -> None:
    if importlib.util.find_spec("sigstore") is not None:  # pragma: no cover
        pytest.skip("sigstore is installed; keyless signing needs OIDC (CI only)")
    with pytest.raises(SignatureError, match="optional extra"):
        sign(PAYLOAD, "sigstore")
