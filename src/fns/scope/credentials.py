"""Credentials for live runs. The only module that touches ``azure.identity``.

Fang & Scale never handles secrets: tokens come from the Azure CLI session
(``az login``, interactively or with GitHub OIDC in CI) through
``AzureCliCredential``, pinned to the scope manifest's tenant.

Tenant pinning (CLAUDE.md rule 3): the tenant a token was issued for is read
from its ``tid`` claim and compared with the manifest before any API call; a
mismatch, or a token without a readable ``tid``, aborts. The claim is read
without verifying the signature. That is fine here: the token comes straight
from the local credential, and the API verifies it on every call. The check
only catches a CLI session signed in to the wrong tenant.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final, Protocol

from fns.models.operations import Api

SCOPES: Final[dict[Api, str]] = {
    "arm": "https://management.azure.com/.default",
    "graph": "https://graph.microsoft.com/.default",
    # Data plane (M3 P5): only `fns prove` sends these, as the test identity.
    "kv": "https://vault.azure.net/.default",
    "blob": "https://storage.azure.com/.default",
}


class CredentialError(RuntimeError):
    """No usable token (not signed in, CLI missing, consent missing)."""


class TenantMismatchError(CredentialError):
    def __init__(self, expected: str, actual: str | None) -> None:
        super().__init__(
            f"signed-in tenant {actual or 'unknown'} does not match scope tenant {expected}"
        )
        self.expected = expected
        self.actual = actual


class _TokenSource(Protocol):
    def get_token(self, *scopes: str, **kwargs: Any) -> Any: ...


class TokenProvider(Protocol):
    def token(self, api: Api) -> str: ...


def token_claims(token: str) -> dict[str, Any]:
    """Decode a JWT payload without verifying it (see module docstring)."""
    try:
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (IndexError, ValueError, binascii.Error) as exc:
        raise CredentialError("access token is not a readable JWT") from exc
    if not isinstance(claims, dict):
        raise CredentialError("access token payload is not an object")
    return claims


def token_tenant(token: str) -> str | None:
    tid = token_claims(token).get("tid")
    try:
        return str(uuid.UUID(str(tid))) if tid else None
    except ValueError:
        return None


class PrincipalMismatchError(CredentialError):
    """A token was issued to another principal than the first one (``oid``)."""


@dataclass(frozen=True, slots=True)
class SignedInIdentity:
    """Who the tokens belong to, from the ARM token's claims (decision V4)."""

    object_id: str
    """``oid``: the service principal's object ID. This is what the gate pins."""
    app_id: str | None
    """``appid`` (v1 tokens) or ``azp`` (v2): the application's client ID."""


def _guid(value: object) -> str | None:
    try:
        return str(uuid.UUID(str(value))) if value else None
    except ValueError:
        return None


def token_identity(token: str) -> SignedInIdentity:
    claims = token_claims(token)
    oid = _guid(claims.get("oid"))
    if oid is None:
        raise CredentialError("access token has no readable oid claim")
    return SignedInIdentity(oid, _guid(claims.get("appid") or claims.get("azp")))


class PinnedTokens:
    """Tokens for one tenant; every token's ``tid`` is checked, not just the first.

    Once :meth:`signed_in_identity` has been called, every later token must also
    carry the same ``oid``: a CLI session that switches identity mid-run aborts.
    """

    REFRESH_MARGIN_SECONDS: Final = 300

    def __init__(
        self,
        tenant_id: str,
        source: _TokenSource | None = None,
        *,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self.tenant_id = str(uuid.UUID(tenant_id))
        self._source = source if source is not None else _cli_credential(self.tenant_id)
        self._wall = wall
        self._cache: dict[Api, tuple[str, float]] = {}
        self._identity: SignedInIdentity | None = None

    def token(self, api: Api) -> str:
        cached = self._cache.get(api)
        if cached is None or cached[1] - self.REFRESH_MARGIN_SECONDS <= self._wall():
            try:
                access = self._source.get_token(SCOPES[api])
                raw, expires_on = access.token, float(access.expires_on)
            except CredentialError:
                raise
            except Exception as exc:
                raise CredentialError(f"could not get a {api} token: {type(exc).__name__}") from exc
            if not isinstance(raw, str):
                raise CredentialError("credential returned a non-string token")
            actual = token_tenant(raw)
            if actual != self.tenant_id:
                raise TenantMismatchError(self.tenant_id, actual)
            if self._identity is not None:
                oid = _guid(token_claims(raw).get("oid"))
                if oid != self._identity.object_id:
                    raise PrincipalMismatchError(
                        f"a {api} token belongs to another principal than the first token"
                    )
            self._cache[api] = (raw, expires_on)
        return self._cache[api][0]

    def signed_in_tenant(self) -> str:
        """Fetch an ARM token and return its tenant (raises on mismatch)."""
        self.token("arm")
        return self.tenant_id

    def signed_in_identity(self) -> SignedInIdentity:
        """``oid`` and ``appid`` of the ARM token; pins every later token to that ``oid``."""
        if self._identity is None:
            self._identity = token_identity(self.token("arm"))
            for api, (raw, _) in self._cache.items():
                if _guid(token_claims(raw).get("oid")) != self._identity.object_id:
                    raise PrincipalMismatchError(f"the cached {api} token is another principal's")
        return self._identity


def _cli_credential(tenant_id: str) -> _TokenSource:
    from azure.identity import AzureCliCredential

    return AzureCliCredential(tenant_id=tenant_id, process_timeout=30)
