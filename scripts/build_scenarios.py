"""Build the scenario gallery's FIXTURE tenants (docs/scenarios/).

Each scenario is a small hand-written tenant spec below. A fake tenant answers the
scout's requests from that spec, the real collector runs against it, and the
exchanges it made are written as a replayable fixture set, so ``fns demo contain
--fixture docs/scenarios/<name>/tenant`` runs the same pipeline as a live scout.
Placeholder GUIDs only (``00000000-0000-4000-8000-...``); Microsoft's public role
and permission IDs are the only other GUIDs. Every set is labelled FIXTURE.

    uv run python scripts/build_scenarios.py          # rewrite docs/scenarios/*
    uv run python scripts/build_scenarios.py --check  # fail if anything drifted

``tests/test_scenarios.py`` runs ``--check`` and compares each ``fns demo contain``
output with the committed ``expected*.txt``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from typer.testing import CliRunner

from fns.adapters.azure import graph
from fns.adapters.azure.http import ApiRequest, ApiResponse
from fns.cli import app
from fns.fixtures import wellknown as wk
from fns.inventory.collector import Collector
from fns.models.scope import parse_scope
from fns.scope.gate import FrozenClock, Gate, InMemoryJournal

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "scenarios"
RECORDED_AT = "2026-11-28T12:00:00Z"
TENANT = "00000000-0000-4000-8000-000000000001"
SUB = "00000000-0000-4000-8000-000000000010"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-app"
ARM = "https://management.azure.com"
GRAPH_SP = "00000000-0000-4000-8000-000000000103"


def pid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


# --- role definitions (built-in IDs and permissions, as ARM returns them) ---------------------

_BLOBS = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs"
ROLES: dict[str, tuple[str, dict[str, list[str]]]] = {
    wk.OWNER: ("Owner", {"actions": ["*"]}),
    wk.CONTRIBUTOR: (
        "Contributor",
        {
            "actions": ["*"],
            "notActions": [
                "Microsoft.Authorization/*/Delete",
                "Microsoft.Authorization/*/Write",
                "Microsoft.Authorization/elevateAccess/Action",
            ],
        },
    ),
    wk.READER: ("Reader", {"actions": ["*/read"]}),
    wk.KEY_VAULT_SECRETS_USER: (
        "Key Vault Secrets User",
        {
            "dataActions": [
                "Microsoft.KeyVault/vaults/secrets/getSecret/action",
                "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
            ]
        },
    ),
    wk.STORAGE_ACCOUNT_KEY_OPERATOR: (
        "Storage Account Key Operator Service Role",
        {
            "actions": [
                "Microsoft.Storage/storageAccounts/listkeys/action",
                "Microsoft.Storage/storageAccounts/regeneratekey/action",
            ]
        },
    ),
    wk.STORAGE_BLOB_DATA_CONTRIBUTOR: (
        "Storage Blob Data Contributor",
        {
            "actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
            "dataActions": [f"{_BLOBS}/read", f"{_BLOBS}/write", f"{_BLOBS}/add/action"],
        },
    ),
}

GRAPH_ROLES = {
    "Application.ReadWrite.OwnedBy": wk.APPLICATION_READWRITE_OWNEDBY,
    "Application.Read.All": wk.APPLICATION_READ_ALL,
}


# --- the spec --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    n: int
    name: str
    managed: bool = False
    owners: tuple[int, ...] = ()
    """Owners of this principal's application (service principals by number)."""
    graph: tuple[str, ...] = ()
    groups: tuple[int, ...] = ()
    """Direct group memberships."""
    passwords: int = 0
    fics: tuple[tuple[str, str], ...] = ()
    """(issuer, subject) federated credentials on its application."""

    @property
    def sp(self) -> str:
        return pid(self.n)

    @property
    def app(self) -> str:
        return pid(self.n + 200)

    @property
    def app_id(self) -> str:
        return pid(self.n + 600)


@dataclass(frozen=True)
class Group:
    n: int
    name: str
    member_of: tuple[int, ...] = ()
    assignable: bool = False


@dataclass(frozen=True)
class Tenant:
    resources: tuple[tuple[str, str], ...]
    """(name, ARM type) in rg-app."""
    principals: tuple[Principal, ...]
    grants: tuple[tuple[int, str, str], ...]
    """(principal or group number, role definition GUID, scope: 'rg' or a resource name)."""
    groups: tuple[Group, ...] = ()
    optional_ops: tuple[str, ...] = ()


@dataclass(frozen=True)
class Scenario:
    slug: str
    title: str
    contract: str
    tenant: Tenant
    fixed: Tenant


# --- the fake tenant ---------------------------------------------------------------------------


def _scope_id(scope: str) -> str:
    if scope == "rg":
        return RG
    for name, rtype in _CURRENT.resources:
        if name == scope:
            return f"{RG}/providers/{rtype}/{name}"
    raise KeyError(scope)


_CURRENT: Tenant


class FakeTenant:
    """Answers exactly the requests the scout makes; anything else is a builder bug."""

    def __init__(self, t: Tenant) -> None:
        self.t = t
        self.exchanges: list[tuple[str, dict[str, Any]]] = []
        self.by_sp = {p.sp: p for p in t.principals}
        self.by_app = {p.app: p for p in t.principals if not p.managed}
        self.groups = {pid(g.n): g for g in t.groups}

    def fetch(self, req: ApiRequest) -> ApiResponse:
        body = self._answer(req)
        self.exchanges.append(
            (
                f"{req.method} {req.url}",
                {"status": 200, "body": body, "request_id": None, "retry_after": None},
            )
        )
        return ApiResponse(200, body, None)

    def _answer(self, req: ApiRequest) -> dict[str, Any]:
        t = self.t
        path = urlsplit(req.url).path
        op = req.operation
        if op == "arm:Microsoft.Resources/subscriptions/resourceGroups/resources/read":
            return {
                "value": [
                    {"id": f"{RG}/providers/{rt}/{n}", "name": n, "type": rt, "location": "westus"}
                    for n, rt in t.resources
                ]
            }
        if op == "arm:Microsoft.Authorization/roleAssignments/read":
            assignments: list[dict[str, Any]] = []
            for i, (who, role, scope) in enumerate(t.grants):
                kind = "Group" if pid(who) in self.groups else "ServicePrincipal"
                sid = _scope_id(scope)
                rid = pid(700 + i)
                assignments.append(
                    {
                        "id": f"{sid}/providers/Microsoft.Authorization/roleAssignments/{rid}",
                        "name": rid,
                        "properties": {
                            "principalId": pid(who),
                            "principalType": kind,
                            "roleDefinitionId": f"/subscriptions/{SUB}/providers/"
                            f"Microsoft.Authorization/roleDefinitions/{role}",
                            "scope": sid,
                            "condition": None,
                            "conditionVersion": None,
                        },
                        "type": "Microsoft.Authorization/roleAssignments",
                    }
                )
            return {"value": assignments}
        if op == "arm:Microsoft.Authorization/roleDefinitions/read":
            guid = path.rsplit("/", 1)[-1]
            name, perms = ROLES[guid]
            full: dict[str, list[str]] = {
                "actions": [],
                "notActions": [],
                "dataActions": [],
                "notDataActions": [],
            }
            defs = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions"
            return {
                "id": f"{defs}/{guid}",
                "name": guid,
                "properties": {
                    "roleName": name,
                    "type": "BuiltInRole",
                    "assignableScopes": ["/"],
                    "permissions": [{**full, **perms}],
                },
                "type": "Microsoft.Authorization/roleDefinitions",
            }
        if op == "arm:Microsoft.Authorization/denyAssignments/read":
            return {"value": []}
        if op == graph.OP_SERVICE_PRINCIPALS:
            rows: list[dict[str, Any]] = [
                {
                    "id": GRAPH_SP,
                    "appId": wk.MICROSOFT_GRAPH_APP_ID,
                    "displayName": "Microsoft Graph",
                    "servicePrincipalType": "Application",
                    "appOwnerOrganizationId": wk.MICROSOFT_SERVICES_TENANT,
                    "appRoles": [
                        {
                            "allowedMemberTypes": ["Application"],
                            "id": rid,
                            "isEnabled": True,
                            "value": value,
                        }
                        for value, rid in sorted(GRAPH_ROLES.items())
                    ],
                }
            ]
            for p in t.principals:
                rows.append(
                    {
                        "id": p.sp,
                        "appId": p.app_id,
                        "displayName": p.name,
                        "servicePrincipalType": "ManagedIdentity" if p.managed else "Application",
                        "appOwnerOrganizationId": None if p.managed else TENANT,
                        "appRoles": [],
                    }
                )
            return {"value": rows}
        if op == graph.OP_APPLICATIONS:
            return {
                "value": [
                    {"id": p.app, "appId": p.app_id, "displayName": p.name}
                    for p in t.principals
                    if not p.managed
                ]
            }
        if op in (graph.OP_SP_OWNERS, graph.OP_APP_OWNERS):
            oid = path.split("/")[3]
            owner_of = self.by_app.get(oid) if op == graph.OP_APP_OWNERS else None
            return {
                "value": [
                    {
                        "@odata.type": "#microsoft.graph.servicePrincipal",
                        "id": self.by_sp[pid(o)].sp,
                        "displayName": self.by_sp[pid(o)].name,
                    }
                    for o in (owner_of.owners if owner_of else ())
                ]
            }
        if op == graph.OP_SP_APP_ROLE_ASSIGNMENTS:
            p = self.by_sp[path.split("/")[3]]
            return {
                "value": [
                    {
                        "id": f"opaque-{p.n}-{i}",
                        "appRoleId": GRAPH_ROLES[v],
                        "principalId": p.sp,
                        "principalType": "ServicePrincipal",
                        "resourceId": GRAPH_SP,
                        "resourceDisplayName": "Microsoft Graph",
                    }
                    for i, v in enumerate(p.graph)
                ]
            }
        if op == graph.OP_SP_MEMBER_OF:
            p = self.by_sp[path.split("/")[3]]
            return {
                "value": [
                    {
                        "@odata.type": "#microsoft.graph.group",
                        "id": pid(g),
                        "displayName": self.groups[pid(g)].name,
                    }
                    for g in p.groups
                ]
            }
        if op == graph.OP_SP_TRANSITIVE_GROUPS:
            p = self.by_sp[path.split("/")[3]]
            seen: list[str] = []
            todo = [pid(g) for g in p.groups]
            while todo:
                g = todo.pop(0)
                if g not in seen:
                    seen.append(g)
                    todo.extend(pid(x) for x in self.groups[g].member_of)
            return {
                "value": [
                    {
                        "id": g,
                        "displayName": self.groups[g].name,
                        "isAssignableToRole": self.groups[g].assignable,
                    }
                    for g in seen
                ]
            }
        if op in (graph.OP_DIR_ROLE_DEFINITIONS, graph.OP_DIR_ROLE_ASSIGNMENTS):
            return {"value": []}
        if op in graph.CREDENTIAL_OPERATIONS:
            oid = path.split("/")[3]
            owner = self.by_app.get(oid) if op == graph.OP_APPLICATION else self.by_sp.get(oid)
            n = owner.n if owner is not None else 0
            count = owner.passwords if owner is not None and op == graph.OP_APPLICATION else 0
            pws = [
                {
                    "keyId": pid(800 + (n * 10) + i),
                    "displayName": f"ci-secret-{i + 1}",
                    "startDateTime": "2026-06-01T00:00:00Z",
                    "endDateTime": "2027-06-01T00:00:00Z",
                    "hint": None,
                    "secretText": None,
                }
                for i in range(count)
            ]
            return {"id": oid, "keyCredentials": [], "passwordCredentials": pws}
        if op == graph.OP_APP_FICS:
            p = self.by_app[path.split("/")[3]]
            return {
                "value": [
                    {
                        "id": pid(850 + (p.n * 10) + i),
                        "name": f"github-{i + 1}",
                        "issuer": iss,
                        "subject": sub,
                        "audiences": ["api://AzureADTokenExchange"],
                    }
                    for i, (iss, sub) in enumerate(p.fics)
                ]
            }
        raise AssertionError(f"the fake tenant does not answer {op} {req.url}")


BASE_OPS = (
    "arm:Microsoft.Authorization/roleAssignments/read",
    "arm:Microsoft.Authorization/roleDefinitions/read",
    "arm:Microsoft.Authorization/denyAssignments/read",
    "arm:Microsoft.Resources/subscriptions/resourceGroups/resources/read",
    graph.OP_SERVICE_PRINCIPALS,
    graph.OP_APPLICATIONS,
    graph.OP_SP_OWNERS,
    graph.OP_APP_OWNERS,
    graph.OP_SP_APP_ROLE_ASSIGNMENTS,
    graph.OP_SP_MEMBER_OF,
    graph.OP_DIR_ROLE_DEFINITIONS,
    graph.OP_DIR_ROLE_ASSIGNMENTS,
)


def scope_yaml(t: Tenant, agent: Principal) -> str:
    ops = "\n".join(f"    - {op}" for op in (*BASE_OPS, *t.optional_ops))
    return f"""# FIXTURE scope for a scenario-gallery tenant (scripts/build_scenarios.py).
# Replay freezes the clock at recorded_at, so this expiry stays valid.
version: 1
tenant_id: {TENANT}
subscription_ids:
  - {SUB}
allowed_resource_groups:
  - {RG}
test_identities:
  - object_id: {agent.sp}
    kind: servicePrincipal
    name: {agent.name}
allowed_operations:
  scout:
{ops}
budget:
  max_api_calls: 200
  max_minutes: 15
expires_at: "2026-12-05T12:00:00Z"
"""


def exchanges(t: Tenant, scope: str) -> list[dict[str, Any]]:
    global _CURRENT
    _CURRENT = t
    clock = FrozenClock(datetime.fromisoformat(RECORDED_AT))
    manifest = parse_scope(scope, now=clock.now())
    fake = FakeTenant(t)
    gate = Gate(manifest, signed_in_tenant=TENANT, journal=InMemoryJournal(), clock=clock)
    Collector(
        manifest=manifest,
        gate=gate,
        transport=fake,
        clock=clock,
        mode="FIXTURE",
        sleep=clock.advance,
    ).run()
    return [{"request": r, "response": resp} for r, resp in fake.exchanges]


def files_for(s: Scenario, which: str) -> dict[str, str]:
    t = s.tenant if which == "tenant" else s.fixed
    agent = t.principals[0]
    scope = scope_yaml(t, agent)
    manifest = {
        "description": f"Scenario gallery ({which}): {s.title}. Hand-written spec in "
        "scripts/build_scenarios.py; placeholder GUIDs only.",
        "format": 1,
        "label": "FIXTURE",
        "name": f"scenario-{s.slug}-{which}",
        "recorded_at": RECORDED_AT,
        "tenant_id": TENANT,
    }
    return {
        "manifest.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        "scope.yaml": scope,
        "exchanges.json": json.dumps(exchanges(t, scope), indent=1, sort_keys=True) + "\n",
        "contract.fns.yaml": s.contract,
    }


_WROTE = re.compile(r"^(FIXTURE wrote ).*$", re.M)


def contain_output(fixture: Path) -> tuple[str, int]:
    """``fns demo contain`` on a fixture set, with the temporary report path removed."""
    with tempfile.TemporaryDirectory() as tmp:
        res = CliRunner().invoke(
            app,
            ["demo", "contain", "--fixture", str(fixture), "--out", tmp],
            env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"},
        )
    text = _WROTE.sub(r"\1<report>.FIXTURE.json", res.output.replace("\r\n", "\n"))
    # The demo prints the fixture path; keep it relative so Windows and Linux agree.
    shown = fixture.relative_to(ROOT).as_posix()
    for form in (fixture.as_posix(), str(fixture)):
        text = text.replace(f"'{form}'", f"'{shown}'")
    return text, res.exit_code


# --- the five scenarios ------------------------------------------------------------------------

GH = "https://token.actions.githubusercontent.com"


def _contract(name: str, who: str, body: str, max_inconclusive: int) -> str:
    return f"""# Scenario gallery contract (FIXTURE). `fns demo contain` evaluates it.
version: 1
contract: {name}
assume_compromised: sp:{who}

{body.strip()}

budget:
  max_critical_reachable: 0
  max_inconclusive: {max_inconclusive}
on_inconclusive: fail
"""


def _scenarios() -> list[Scenario]:
    vault = (("kv-crown", "Microsoft.KeyVault/vaults"),)
    out: list[Scenario] = []

    # 1. The agent owns a privileged application.
    agent = Principal(100, "sp-report-agent", graph=("Application.ReadWrite.OwnedBy",))
    deployer = Principal(101, "app-deployer", owners=(100,), passwords=1)
    t = Tenant(
        vault,
        (agent, deployer),
        ((101, wk.KEY_VAULT_SECRETS_USER, "kv-crown"),),
        optional_ops=graph.CREDENTIAL_OPERATIONS,
    )
    out.append(
        Scenario(
            "01-owner-of-privileged-app",
            "the agent owns a privileged application",
            _contract(
                "report-agent-blast-radius",
                agent.name,
                """
must_not_reach:
  - resource: kv-crown
    operations: [secrets/get]
""",
                1,
            ),
            t,
            replace(t, principals=(agent, replace(deployer, owners=()))),
        )
    )

    # 2. Contributor on the resource group flips the vault to access policies.
    agent = Principal(100, "sp-batch-agent")
    t = Tenant(
        (*vault, ("stbatch", "Microsoft.Storage/storageAccounts")),
        (agent,),
        ((100, wk.CONTRIBUTOR, "rg"),),
    )
    out.append(
        Scenario(
            "02-contributor-key-vault-flip",
            "Contributor on the resource group reaches the vault's secrets",
            _contract(
                "batch-agent-blast-radius",
                agent.name,
                """
must_not_reach:
  - resource: kv-crown
    operations: [secrets/get, secrets/list]
must_still_do:
  - resource: stbatch
    operations: [blob/write]
""",
                3,
            ),
            t,
            replace(t, grants=((100, wk.STORAGE_BLOB_DATA_CONTRIBUTOR, "stbatch"),)),
        )
    )

    # 3. listKeys on a storage account is data access.
    agent = Principal(100, "sp-rotation-agent")
    t = Tenant(
        (("stpayroll", "Microsoft.Storage/storageAccounts"),),
        (agent,),
        ((100, wk.STORAGE_ACCOUNT_KEY_OPERATOR, "stpayroll"),),
    )
    out.append(
        Scenario(
            "03-listkeys-is-data-access",
            "a key operator role reads every blob",
            _contract(
                "rotation-agent-blast-radius",
                agent.name,
                """
must_not_reach:
  - resource: stpayroll
    operations: [blob/read, blob/write]
""",
                2,
            ),
            t,
            replace(t, grants=((100, wk.READER, "stpayroll"),)),
        )
    )

    # 4. A GitHub federated credential trusts every pull request.
    agent = Principal(100, "sp-deployer", fics=((GH, "repo:contoso/billing:pull_request"),))
    t = Tenant(
        (("kv-deploy", "Microsoft.KeyVault/vaults"), *vault),
        (agent,),
        ((100, wk.KEY_VAULT_SECRETS_USER, "kv-deploy"),),
        optional_ops=graph.FIC_OPERATIONS,
    )
    out.append(
        Scenario(
            "04-github-trust-too-broad",
            "a GitHub federated credential trusts every pull request",
            _contract(
                "deployer-blast-radius",
                agent.name,
                """
must_not_reach:
  - resource: kv-crown
    operations: [secrets/get]
must_still_do:
  - resource: kv-deploy
    operations: [secrets/get]
""",
                2,
            ),
            t,
            replace(
                t,
                principals=(
                    replace(agent, fics=((GH, "repo:contoso/billing:environment:production"),)),
                ),
            ),
        )
    )

    # 5. A nested group holds a privileged role.
    agent = Principal(100, "sp-sync-agent", groups=(130,))
    t = Tenant(
        vault,
        (agent,),
        ((131, wk.OWNER, "rg"),),
        groups=(
            Group(130, "grp-sync-workers", member_of=(131,)),
            Group(131, "grp-platform-admins"),
        ),
        optional_ops=graph.MEMBERSHIP_OPERATIONS,
    )
    out.append(
        Scenario(
            "05-nested-group-owner",
            "a nested group makes the agent Owner",
            _contract(
                "sync-agent-blast-radius",
                agent.name,
                """
must_not_reach:
  - resource: kv-crown
    operations: [secrets/get, roleAssignments/write]
""",
                2,
            ),
            t,
            replace(t, groups=(Group(130, "grp-sync-workers"), Group(131, "grp-platform-admins"))),
        )
    )
    return out


SCENARIOS = _scenarios()


def build(check: bool) -> list[str]:
    drift: list[str] = []
    for s in SCENARIOS:
        base = OUT / s.slug
        for which in ("tenant", "fixed"):
            for name, text in files_for(s, which).items():
                path = base / which / name
                if path.exists() and path.read_text(encoding="utf-8") == text:
                    continue
                drift.append(str(path.relative_to(ROOT)))
                if not check:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text, encoding="utf-8", newline="\n")
            output, code = contain_output(base / which)
            expected = base / f"expected-{which}.txt"
            text = (
                f"$ uv run fns demo contain --fixture docs/scenarios/{s.slug}/{which}\n"
                f"{output}(exit {code})\n"
            )
            if not (expected.exists() and expected.read_text(encoding="utf-8") == text):
                drift.append(str(expected.relative_to(ROOT)))
                if not check:
                    expected.write_text(text, encoding="utf-8", newline="\n")
    return drift


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    check: bool = parser.parse_args().check
    drift = build(check)
    for d in drift:
        sys.stdout.write(("drifted: " if check else "wrote: ") + d + "\n")
    return 1 if drift and check else 0


if __name__ == "__main__":
    raise SystemExit(main())
