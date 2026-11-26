"""Tenant pinning (CLAUDE.md rule 3) and token handling. Negative tests first."""

from __future__ import annotations

import pytest

from fns.scope.credentials import (
    SCOPES,
    CredentialError,
    PinnedTokens,
    TenantMismatchError,
    token_claims,
    token_tenant,
)
from tests.factories import OTHER_TENANT, TENANT
from tests.livekit import FakeCredential, fake_jwt


def test_token_tenant_reads_tid_claim() -> None:
    assert token_tenant(fake_jwt(tid=TENANT.upper())) == TENANT
    assert token_tenant(fake_jwt(oid="x")) is None
    assert token_tenant(fake_jwt(tid="not-a-guid")) is None


@pytest.mark.parametrize("bad", ["", "abc", "a.!!!.c", "a.bnVsbA.c"])
def test_unreadable_tokens_are_rejected(bad: str) -> None:
    with pytest.raises(CredentialError):
        token_claims(bad)


def test_mismatched_tenant_aborts() -> None:
    tokens = PinnedTokens(TENANT, FakeCredential({"arm": OTHER_TENANT}))
    with pytest.raises(TenantMismatchError) as info:
        tokens.signed_in_tenant()
    assert info.value.actual == OTHER_TENANT
    assert info.value.expected == TENANT


def test_token_without_tid_aborts() -> None:
    with pytest.raises(TenantMismatchError):
        PinnedTokens(TENANT, FakeCredential({"arm": None})).token("arm")


def test_every_api_token_is_pinned_not_only_the_first() -> None:
    tokens = PinnedTokens(TENANT, FakeCredential({"arm": TENANT, "graph": OTHER_TENANT}))
    assert tokens.signed_in_tenant() == TENANT
    with pytest.raises(TenantMismatchError):
        tokens.token("graph")


def test_credential_failures_fail_closed() -> None:
    cred = FakeCredential({"arm": TENANT}, error=RuntimeError("az not found"))
    with pytest.raises(CredentialError, match="could not get a arm token"):
        PinnedTokens(TENANT, cred).token("arm")


def test_tokens_are_cached_and_refreshed_before_expiry() -> None:
    now = [0.0]
    cred = FakeCredential({"arm": TENANT}, expires_on=1000)
    tokens = PinnedTokens(TENANT, cred, wall=lambda: now[0])
    tokens.token("arm")
    tokens.token("arm")
    assert cred.calls == [SCOPES["arm"]]
    now[0] = 1000 - PinnedTokens.REFRESH_MARGIN_SECONDS
    tokens.token("arm")
    assert len(cred.calls) == 2


def test_refreshed_token_is_pinned_again() -> None:
    now = [0.0]
    cred = FakeCredential({"arm": TENANT}, expires_on=1000)
    tokens = PinnedTokens(TENANT, cred, wall=lambda: now[0])
    tokens.token("arm")
    cred.tids["arm"] = OTHER_TENANT
    now[0] = 2000
    with pytest.raises(TenantMismatchError):
        tokens.token("arm")


def test_scopes_are_dot_default_for_both_apis() -> None:
    assert SCOPES == {
        "arm": "https://management.azure.com/.default",
        "graph": "https://graph.microsoft.com/.default",
    }


def test_rejects_non_guid_tenant() -> None:
    with pytest.raises(ValueError):
        PinnedTokens("contoso.onmicrosoft.com", FakeCredential({}))
