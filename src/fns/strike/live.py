"""Live strikes: two identities, each signed in in its own Azure CLI config dir.

``sp-billing-agent`` writes and ``sp-fns-scout`` reads (M4 strike plan, step 5).
The Azure CLI keeps one sign-in per config dir, so the operator signs in twice:

    $env:AZURE_CONFIG_DIR = "$HOME\\.fns\\az-agent"; az login --service-principal ...
    $env:AZURE_CONFIG_DIR = "$HOME\\.fns\\az-scout"; az login --service-principal ...

and passes both dirs (``--agent-config``, ``--scout-config``). Before anything is
sent, both tokens must carry the scope's tenant. The agent must be the scope's
test identity (and its ``appid`` must match when the scope lists one). The scout
must be someone else, and not a test identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fns.models.scope import ScopeManifest
from fns.scope.credentials import ConfigDirSource, PinnedTokens, SignedInIdentity


class StrikeIdentityError(RuntimeError):
    """The signed-in identities are not the ones a strike needs (exit 4)."""


@dataclass(frozen=True, slots=True)
class StrikeIdentities:
    tenant_id: str
    agent: SignedInIdentity
    scout: SignedInIdentity
    agent_tokens: PinnedTokens
    scout_tokens: PinnedTokens


def sign_in(
    manifest: ScopeManifest,
    agent_tokens: PinnedTokens,
    scout_tokens: PinnedTokens,
) -> StrikeIdentities:
    """Check both sign-ins before any API call; raise on anything unexpected."""
    tenant = agent_tokens.signed_in_tenant()  # TenantMismatchError if not the scope's
    if scout_tokens.signed_in_tenant() != tenant:
        raise StrikeIdentityError("the scout is signed in to another tenant")
    agent = agent_tokens.signed_in_identity()
    scout = scout_tokens.signed_in_identity()
    ident = next((i for i in manifest.test_identities if str(i.object_id) == agent.object_id), None)
    if ident is None:
        raise StrikeIdentityError(
            f"the agent config is signed in as {agent.object_id}, not a test identity"
        )
    if ident.app_id is not None and str(ident.app_id) != agent.app_id:
        raise StrikeIdentityError("the agent token's appid does not match the scope's app_id")
    if scout.object_id == agent.object_id:
        raise StrikeIdentityError("the scout and the agent are the same identity")
    if any(str(i.object_id) == scout.object_id for i in manifest.test_identities):
        raise StrikeIdentityError("the scout must not be a test identity")
    return StrikeIdentities(tenant, agent, scout, agent_tokens, scout_tokens)


def cli_identities(
    manifest: ScopeManifest, agent_config: Path, scout_config: Path
) -> StrikeIdentities:
    if agent_config.resolve() == scout_config.resolve():
        raise StrikeIdentityError("--agent-config and --scout-config must be different dirs")
    tenant = str(manifest.tenant_id)
    return sign_in(
        manifest,
        PinnedTokens(tenant, ConfigDirSource(tenant, agent_config)),
        PinnedTokens(tenant, ConfigDirSource(tenant, scout_config)),
    )
