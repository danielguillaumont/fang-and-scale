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


class PinnedTokens:
    """Tokens for one tenant; every token's ``tid`` is checked, not just the first."""

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
            self._cache[api] = (raw, expires_on)
        return self._cache[api][0]

    def signed_in_tenant(self) -> str:
        """Fetch an ARM token and return its tenant (raises on mismatch)."""
        self.token("arm")
        return self.tenant_id


def _cli_credential(tenant_id: str) -> _TokenSource:
    from azure.identity import AzureCliCredential

    return AzureCliCredential(tenant_id=tenant_id, process_timeout=30)
