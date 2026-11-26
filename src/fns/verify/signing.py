"""in-toto Statement v1 in a DSSE envelope, and the signers that sign it.

- ``offline-test``: an ephemeral Ed25519 key. Proves integrity against that key
  only; anyone can make another. Always labelled ``TEST SIGNATURE``.
- ``sigstore``: keyless signing with sigstore-python 4.x and the ambient OIDC
  token (GitHub Actions). Optional extra; Sigstore itself is only reached from
  CI (M3 E5). **Staging only** (decision V3): ``FNS_SIGSTORE_INSTANCE`` selects
  the instance, and production is refused until the owner approves it.
- ``none``: the statement is written unsigned, and says so.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fns.models.base import canonical_dumps
from fns.models.bundle import DSSE_PAYLOAD_TYPE, PREDICATE_TYPE, STATEMENT_TYPE, EvidenceBundle

SignerName = Literal["offline-test", "sigstore", "none"]
TEST_WARNING: Final = "TEST SIGNATURE: integrity only, not identity, not Sigstore"
UNSIGNED_WARNING: Final = "UNSIGNED: the statement carries no signature"

SigstoreInstance = Literal["staging", "production"]
INSTANCE_ENV: Final = "FNS_SIGSTORE_INSTANCE"
STAGING_WARNING: Final = (
    "SIGSTORE STAGING: signed on Sigstore's test instance; proves the pipeline, "
    "not a trusted public log"
)
PRODUCTION_APPROVED: Final = False
"""V3: production Fulcio and Rekor only after the owner's explicit approval
(docs/DECISIONS.md). Until then a production request is refused before any
network contact, for signing and for verification alike."""


class SignatureError(RuntimeError):
    pass


def statement(bundle: EvidenceBundle, subjects: dict[str, str]) -> bytes:
    """Canonical in-toto Statement bytes: these are exactly what gets signed."""
    body = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": name, "digest": {"sha256": digest}}
            for name, digest in sorted(subjects.items())
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": json.loads(bundle.canonical_json()),
    }
    return canonical_dumps(body).encode("utf-8")


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: object) -> bytes:
    if not isinstance(text, str):
        raise SignatureError("expected base64 text")
    try:
        return base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise SignatureError("invalid base64") from exc


@dataclass(frozen=True, slots=True)
class Signed:
    envelope: dict[str, Any]
    signing: dict[str, Any]
    """Written to ``signing.json``: signer, warning, public key or Sigstore bundle."""


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id(public: bytes) -> str:
    return "offline-test:" + hashlib.sha256(public).hexdigest()[:16]


def sign_offline(payload: bytes, key: Ed25519PrivateKey | None = None) -> Signed:
    key = key or Ed25519PrivateKey.generate()
    public = _raw_public(key.public_key())
    sig = key.sign(pae(DSSE_PAYLOAD_TYPE, payload))
    envelope = {
        "payload": _b64(payload),
        "payloadType": DSSE_PAYLOAD_TYPE,
        "signatures": [{"keyid": key_id(public), "sig": _b64(sig)}],
    }
    return Signed(
        envelope,
        {"signer": "offline-test", "warning": TEST_WARNING, "public_key": _b64(public)},
    )


def unsigned(payload: bytes) -> Signed:
    envelope = {"payload": _b64(payload), "payloadType": DSSE_PAYLOAD_TYPE, "signatures": []}
    return Signed(envelope, {"signer": "none", "warning": UNSIGNED_WARNING})


def _sigstore(module: str) -> Any:
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        raise SignatureError(
            "sigstore signing needs the optional extra: uv sync --extra sigstore"
        ) from exc


def sigstore_instance(env: Mapping[str, str] | None = None) -> SigstoreInstance:
    """The Sigstore instance to use: ``staging`` unless set, production refused (V3)."""
    value = (os.environ if env is None else env).get(INSTANCE_ENV, "staging")
    if value == "staging":
        return "staging"
    if value == "production":
        if PRODUCTION_APPROVED:  # pragma: no cover - not yet approved
            return "production"
        raise SignatureError(
            "Sigstore production is not enabled: it needs the owner's explicit approval "
            f"(decision V3, docs/DECISIONS.md). Use {INSTANCE_ENV}=staging"
        )
    raise SignatureError(f"unknown {INSTANCE_ENV} {value!r} (staging or production)")


def sign_sigstore(payload: bytes, instance: SigstoreInstance | None = None) -> Signed:
    """Keyless signing (sigstore-python 4.x) with the ambient OIDC token.

    The instance is checked before sigstore is imported, so a refused instance
    never reaches the network.
    """
    instance = sigstore_instance({INSTANCE_ENV: instance} if instance else None)
    sign, models, oidc, dsse = (
        _sigstore(m) for m in ("sigstore.sign", "sigstore.models", "sigstore.oidc", "sigstore.dsse")
    )
    trust = (
        models.ClientTrustConfig.staging()
        if instance == "staging"
        else models.ClientTrustConfig.production()
    )
    token = oidc.IdentityToken(oidc.detect_credential())
    ctx = sign.SigningContext.from_trust_config(trust)
    with ctx.signer(token) as signer:
        bundle = signer.sign_dsse(dsse.Statement(payload))
    sigstore_bundle = json.loads(bundle.to_json())
    envelope = sigstore_bundle.get("dsseEnvelope", {})
    signing: dict[str, Any] = {
        "signer": "sigstore",
        "sigstore_bundle": sigstore_bundle,
        "sigstore_instance": instance,
    }
    if instance == "staging":
        signing["warning"] = STAGING_WARNING
    return Signed(envelope, signing)


def sign(payload: bytes, signer: SignerName) -> Signed:
    if signer == "offline-test":
        return sign_offline(payload)
    if signer == "sigstore":
        return sign_sigstore(payload)
    return unsigned(payload)


def verify_envelope(
    envelope: dict[str, Any],
    signing: dict[str, Any],
    *,
    sigstore_identity: str | None = None,
    sigstore_issuer: str | None = None,
) -> bytes:
    """Return the verified payload, or raise :class:`SignatureError`."""
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise SignatureError("unexpected DSSE payload type")
    payload = _unb64(envelope.get("payload"))
    signer = signing.get("signer")
    if signer == "offline-test":
        public = _unb64(signing.get("public_key"))
        sigs = envelope.get("signatures")
        if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict):
            raise SignatureError("expected exactly one signature")
        if sigs[0].get("keyid") != key_id(public):
            raise SignatureError("signature key id does not match the public key")
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                _unb64(sigs[0].get("sig")), pae(DSSE_PAYLOAD_TYPE, payload)
            )
        except (InvalidSignature, ValueError) as exc:
            raise SignatureError("signature does not verify") from exc
        return payload
    if signer == "sigstore":
        if not (sigstore_identity and sigstore_issuer):
            raise SignatureError("sigstore verification needs --identity and --issuer")
        instance = sigstore_instance()
        recorded = signing.get("sigstore_instance")
        if recorded != instance:
            raise SignatureError(
                f"the bundle says it was signed on Sigstore {recorded or 'unknown'}; "
                f"this verifier is set to {instance}"
            )
        verify, models, policy = (
            _sigstore(m) for m in ("sigstore.verify", "sigstore.models", "sigstore.verify.policy")
        )
        verifier = (
            verify.Verifier.staging() if instance == "staging" else verify.Verifier.production()
        )
        bundle = models.Bundle.from_json(json.dumps(signing.get("sigstore_bundle")))
        _, verified = verifier.verify_dsse(
            bundle, policy.Identity(identity=sigstore_identity, issuer=sigstore_issuer)
        )
        if verified != payload:
            raise SignatureError("Sigstore-verified payload differs from the envelope")
        return payload
    if signer == "none":
        raise SignatureError("the statement is unsigned")
    raise SignatureError(f"unknown signer {signer!r}")
