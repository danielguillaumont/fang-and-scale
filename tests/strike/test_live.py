"""Live strike sign-in: two identities, both checked before any API call (mocked)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from fns.scope.credentials import (
    ConfigDirSource,
    CredentialError,
    PinnedTokens,
    TenantMismatchError,
)
from fns.strike.live import StrikeIdentityError, cli_identities, sign_in
from tests.factories import SP_AGENT, TENANT, pid
from tests.livekit import AccessToken, fake_jwt
from tests.strike.faketenant import SCOUT, manifest

AGENT_APPID = pid(310)
OTHER_TENANT = pid(999)


@dataclass
class As:
    """A token source for one identity; records AZURE_CONFIG_DIR at each call."""

    oid: str
    tid: str = TENANT
    appid: str = AGENT_APPID
    seen_dirs: list[str | None] = field(default_factory=list)

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        self.seen_dirs.append(os.environ.get("AZURE_CONFIG_DIR"))
        return AccessToken(fake_jwt(tid=self.tid, oid=self.oid, appid=self.appid), 10_000)


def tokens(src: As) -> PinnedTokens:
    return PinnedTokens(TENANT, src, wall=lambda: 0.0)


def test_agent_and_scout_ok() -> None:
    ids = sign_in(manifest(), tokens(As(SP_AGENT)), tokens(As(SCOUT)))
    assert ids.agent.object_id == SP_AGENT and ids.scout.object_id == SCOUT
    assert ids.tenant_id == TENANT


@pytest.mark.parametrize(
    ("agent", "scout", "error", "match"),
    [
        (As(SP_AGENT, tid=OTHER_TENANT), As(SCOUT), TenantMismatchError, None),
        (As(SP_AGENT), As(SCOUT, tid=OTHER_TENANT), TenantMismatchError, None),
        (As(SCOUT), As(SCOUT), StrikeIdentityError, "not a test identity"),
        (As(SP_AGENT), As(SP_AGENT), StrikeIdentityError, "must not be a test identity|same"),
    ],
)
def test_refusals(agent: As, scout: As, error: type[Exception], match: str | None) -> None:
    with pytest.raises(error, match=match):
        sign_in(manifest(), tokens(agent), tokens(scout))


def test_agent_appid_must_match_when_listed() -> None:
    m = manifest(
        test_identities=[
            {"object_id": SP_AGENT, "kind": "servicePrincipal", "name": "agent", "app_id": pid(311)}
        ]
    )
    with pytest.raises(StrikeIdentityError, match="appid"):
        sign_in(m, tokens(As(SP_AGENT)), tokens(As(SCOUT)))


def test_config_dir_is_set_only_during_the_call(tmp_path: Path) -> None:
    before = os.environ.get("AZURE_CONFIG_DIR")
    src = As(SP_AGENT)
    ConfigDirSource(TENANT, tmp_path, inner=src).get_token("https://management.azure.com/.default")
    assert src.seen_dirs == [str(tmp_path)]
    assert os.environ.get("AZURE_CONFIG_DIR") == before


def test_config_dir_is_restored_after_an_error(tmp_path: Path) -> None:
    class Boom:
        def get_token(self, *scopes: str, **kwargs: Any) -> Any:
            raise RuntimeError("az failed")

    before = os.environ.get("AZURE_CONFIG_DIR")
    with pytest.raises(RuntimeError):
        ConfigDirSource(TENANT, tmp_path, inner=Boom()).get_token("x")
    assert os.environ.get("AZURE_CONFIG_DIR") == before


def test_missing_config_dir(tmp_path: Path) -> None:
    with pytest.raises(CredentialError, match="config dir"):
        ConfigDirSource(TENANT, tmp_path / "nope", inner=As(SP_AGENT))


def test_one_dir_for_both_is_refused(tmp_path: Path) -> None:
    with pytest.raises(StrikeIdentityError, match="different"):
        cli_identities(manifest(), tmp_path, tmp_path)
