"""The strikes, as data: every write in order, with its undo (M4 strike plan).

Before harden (session C): S1 ``listKeys`` (undo: regenerate both keys, SD1), S2 a
tag on the vault (undo: the pre-state tags), S3 a 1-hour password on
``app-escalation-target`` (undo: ``removePassword``). S4 comes with its own PR:
it signs in as the escalated identity, which the gate does not allow yet.

After harden (session D, D6): D-1 to D-5 must be denied. Each has the undo that
runs if it is not.

Everything a strike writes carries the run ID: the credential name
``fns-strike-<run>`` and the tag ``fns-strike: <run>``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from fns.adapters.azure.http import ARM_BASE, GRAPH_BASE
from fns.models.operations import WRITE_FORM_OPERATIONS
from fns.models.scope import ScopeManifest
from fns.scope.writes import ARM_API_VERSIONS, CREDENTIAL_PREFIX
from fns.strike.plan import (
    AFTER_HARDEN,
    BEFORE_HARDEN,
    PLAN_LIFETIME,
    PlanError,
    PlannedRequest,
    PlannedWrite,
    StrikeId,
    StrikePlan,
    new_run_id,
)
from fns.strike.reader import LabReader

(
    LIST_KEYS,
    REGEN_KEY,
    VAULT_WRITE,
    ADD_PASSWORD,
    REMOVE_PASSWORD,
    APP_PATCH,
    ASSIGN,
    UNASSIGN,
    ADD_OWNER,
    REMOVE_OWNER,
) = WRITE_FORM_OPERATIONS

STRIKE_TAG: Final = "fns-strike"
USED_FORMS: Final[tuple[str, ...]] = (
    LIST_KEYS,
    REGEN_KEY,
    VAULT_WRITE,
    ADD_PASSWORD,
    REMOVE_PASSWORD,
    ADD_OWNER,
    REMOVE_OWNER,
)
"""The write forms S1 to S3 and D-1 to D-5 use. S4's three (``PATCH`` app roles,
assign, unassign) are left out until S4 is built."""
SUPPORTED: Final[frozenset[str]] = frozenset((*BEFORE_HARDEN, *AFTER_HARDEN))


@dataclass(frozen=True, slots=True)
class LabTargets:
    """The scope's ``strike.targets``, by role. Resolved by Terraform's names."""

    agent: str
    payroll: str | None = None
    vault: str | None = None
    escalation_app: str | None = None
    verifier_app: str | None = None
    scout_app: str | None = None

    def as_dict(self) -> dict[str, str]:
        roles = ("payroll", "vault", "escalation_app", "verifier_app", "scout_app")
        out = {"agent": self.agent}
        out.update({r: v for r in roles if (v := getattr(self, r)) is not None})
        return out

    @classmethod
    def from_dict(cls, roles: dict[str, str]) -> LabTargets:
        return cls(**roles)


def lab_targets(manifest: ScopeManifest) -> LabTargets:
    if manifest.strike is None:
        raise PlanError("the scope has no strike: block (lab/scope.tf renders it)")
    agents = [i for i in manifest.test_identities if i.name == "sp-billing-agent"]
    if not agents and len(manifest.test_identities) == 1:
        agents = list(manifest.test_identities)
    if len(agents) != 1:
        raise PlanError("the scope must name exactly one agent (test identity sp-billing-agent)")
    found: dict[str, str] = {}
    for t in manifest.strike.targets:
        if t.kind == "arm":
            name = t.key.rsplit("/", 1)[-1]
            role = "payroll" if name.startswith("stpayroll") else None
            role = "vault" if name.startswith("kv-crown") else role
        elif t.kind == "graph-application":
            role = {
                "app-escalation-target": "escalation_app",
                "id-verifier": "verifier_app",
                "sp-fns-scout": "scout_app",
            }.get(t.display_name or "")
        else:
            role = None  # service principals: S4
        if role is None:
            continue
        if role in found:
            raise PlanError(f"two strike targets for {role}")
        found[role] = t.id if t.kind == "arm" else t.key.lower()
    return LabTargets(agent=str(agents[0].object_id).lower(), **found)


def _need(value: str | None, what: str) -> str:
    if value is None:
        raise PlanError(f"the scope's strike targets have no {what}")
    return value


def _arm(arm_id: str, suffix: str, kind: str) -> str:
    return f"{ARM_BASE}{arm_id}{suffix}?api-version={ARM_API_VERSIONS[kind]}"


def _add_password(key: str, strike: StrikeId, app: str, run_id: str, end: str) -> PlannedWrite:
    return PlannedWrite(
        key=key,
        strike=strike,
        request=PlannedRequest(
            operation=ADD_PASSWORD,
            method="POST",
            url=f"{GRAPH_BASE}/applications/{app}/addPassword",
            body={
                "passwordCredential": {
                    "displayName": f"{CREDENTIAL_PREFIX}{run_id}",
                    "endDateTime": end,
                }
            },
            learn=("keyId",),
        ),
        expect="allowed" if strike == "S3" else "denied",
        undo=(
            PlannedRequest(
                operation=REMOVE_PASSWORD,
                method="POST",
                url=f"{GRAPH_BASE}/applications/{app}/removePassword",
                body={"keyId": f"{{{{learned:{key}:keyId}}}}"},
            ),
        ),
        lab_objects=(app,),
    )


def _add_owner(key: str, strike: StrikeId, app: str, agent: str) -> PlannedWrite:
    return PlannedWrite(
        key=key,
        strike=strike,
        request=PlannedRequest(
            operation=ADD_OWNER,
            method="POST",
            url=f"{GRAPH_BASE}/applications/{app}/owners/$ref",
            body={"@odata.id": f"{GRAPH_BASE}/directoryObjects/{agent}"},
        ),
        expect="denied",
        undo=(
            PlannedRequest(
                operation=REMOVE_OWNER,
                method="DELETE",
                url=f"{GRAPH_BASE}/applications/{app}/owners/{agent}/$ref",
            ),
        ),
        lab_objects=(app,),
    )


def _app_state(reader: LabReader, app: str) -> dict[str, Any]:
    body = reader.application(app)
    creds = body.get("passwordCredentials")
    return {
        "displayName": body.get("displayName"),
        "passwordCredentials": sorted(
            (
                {"keyId": str(c.get("keyId")).lower(), "displayName": c.get("displayName")}
                for c in (creds if isinstance(creds, list) else [])
                if isinstance(c, dict)
            ),
            key=lambda c: c["keyId"],
        ),
    }


ARM_LAB_TAGS: Final[dict[str, str]] = {"project": "fang-and-scale", "purpose": "lab"}
"""``local.tags`` in ``lab/main.tf``: every lab Azure resource carries both."""


def _lab_tagged(body: dict[str, Any], what: str) -> dict[str, str]:
    tags = body.get("tags") or {}
    if not isinstance(tags, dict):
        raise PlanError(f"the {what}'s tags are not a map")
    clean = {str(k): str(v) for k, v in tags.items()}
    if any(clean.get(k) != v for k, v in ARM_LAB_TAGS.items()):
        raise PlanError(f"the {what} lacks the lab tags {ARM_LAB_TAGS}: not a lab resource")
    return clean


def read_pre_state(strikes: Sequence[StrikeId], t: LabTargets, reader: LabReader) -> dict[str, Any]:
    """What the verification compares against, read as the scout."""
    state: dict[str, Any] = {}
    for s in strikes:
        if s == "S1":
            p = _need(t.payroll, "payroll storage account")
            body = reader.storage_account(p)
            _lab_tagged(body, "payroll storage account")
            props = body.get("properties", {})
            times = props.get("keyCreationTime") if isinstance(props, dict) else None
            if not isinstance(times, dict) or not {"key1", "key2"} <= set(times):
                raise PlanError("the payroll account read has no keyCreationTime")
            state[f"arm:{p}"] = {
                "keyCreationTime": {"key1": str(times["key1"]), "key2": str(times["key2"])}
            }
        elif s == "S2":
            v = _need(t.vault, "Key Vault")
            state[f"arm:{v}"] = {"tags": _lab_tagged(reader.vault(v), "Key Vault")}
    for app in sorted(set(_apps(strikes, t))):
        state[f"app:{app}"] = _app_state(reader, app)
    for app in sorted(set(_owner_apps(strikes, t))):
        state[f"owners:{app}"] = {"owners": reader.app_owners(app)}
    return state


def _apps(strikes: Sequence[StrikeId], t: LabTargets) -> list[str]:
    out = []
    for s in strikes:
        if s in ("S3", "D-1"):
            out.append(_need(t.escalation_app, "app-escalation-target"))
        elif s in ("D-2", "D-4"):
            out.append(_need(t.verifier_app, "id-verifier"))
        elif s in ("D-3", "D-5"):
            out.append(_need(t.scout_app, "sp-fns-scout"))
    return out


def _owner_apps(strikes: Sequence[StrikeId], t: LabTargets) -> list[str]:
    return [
        _need(t.verifier_app if s == "D-4" else t.scout_app, "app")
        for s in strikes
        if s in ("D-4", "D-5")
    ]


OBSERVES: Final[dict[str, tuple[str, ...]]] = {
    "D-1": ("escalation path first hop: ownership without OwnedBy",),
    "D-2": (
        "application:id-verifier credentials/update",
        "directory:tenant applications/credentials/update",
    ),
    "D-3": ("application:sp-fns-scout credentials/update",),
    "D-4": ("application:id-verifier owners/update",),
    "D-5": ("application:sp-fns-scout owners/update",),
}
"""The strike plan's D6 table, column "Contract item it observes"."""


def planned_writes(
    strikes: Sequence[StrikeId],
    t: LabTargets,
    pre_state: dict[str, Any],
    run_id: str,
    created_at: datetime,
) -> tuple[PlannedWrite, ...]:
    end = (created_at + PLAN_LIFETIME).strftime("%Y-%m-%dT%H:%M:%SZ")
    writes: list[PlannedWrite] = []
    for s in strikes:
        if s == "S1":
            p = _need(t.payroll, "payroll storage account")
            writes.append(
                PlannedWrite(
                    key="S1/list-keys",
                    strike="S1",
                    request=PlannedRequest(
                        operation=LIST_KEYS, method="POST", url=_arm(p, "/listKeys", "blob")
                    ),
                    expect="allowed",
                    undo=tuple(
                        PlannedRequest(
                            operation=REGEN_KEY,
                            method="POST",
                            url=_arm(p, "/regenerateKey", "blob"),
                            body={"keyName": k},
                        )
                        for k in ("key1", "key2")
                    ),
                )
            )
        elif s == "S2":
            v = _need(t.vault, "Key Vault")
            before = dict(pre_state[f"arm:{v}"]["tags"])
            if STRIKE_TAG in before:
                raise PlanError(f"the vault already has a {STRIKE_TAG} tag: clean up first")
            writes.append(
                PlannedWrite(
                    key="S2/vault-tag",
                    strike="S2",
                    request=PlannedRequest(
                        operation=VAULT_WRITE,
                        method="PATCH",
                        url=_arm(v, "", "kv"),
                        body={"tags": {**before, STRIKE_TAG: run_id}},
                    ),
                    expect="allowed",
                    undo=(
                        PlannedRequest(
                            operation=VAULT_WRITE,
                            method="PATCH",
                            url=_arm(v, "", "kv"),
                            body={"tags": before},
                        ),
                    ),
                )
            )
        elif s == "S3":
            app = _need(t.escalation_app, "app-escalation-target")
            writes.append(_add_password("S3/add-password", "S3", app, run_id, end))
        elif s in ("D-1", "D-2", "D-3"):
            app = _apps([s], t)[0]
            writes.append(_add_password(f"{s}/add-password", s, app, run_id, end))
        elif s in ("D-4", "D-5"):
            app = _owner_apps([s], t)[0]
            writes.append(_add_owner(f"{s}/add-owner", s, app, t.agent))
        else:
            raise PlanError(f"{s} is not built yet")
    return tuple(
        w.model_copy(update={"observes": OBSERVES[w.strike]}) if w.strike in OBSERVES else w
        for w in writes
    )


def build_plan(
    strikes: Sequence[StrikeId],
    manifest: ScopeManifest,
    scope_sha256: str,
    reader: LabReader,
    now: datetime,
    *,
    run_id: str | None = None,
) -> StrikePlan:
    """Resolve the targets, read the pre-state (as the scout), and lay out every write."""
    unknown = [s for s in strikes if s not in SUPPORTED]
    if unknown:
        raise PlanError(f"not built yet: {', '.join(unknown)}")
    if len(set(strikes)) != len(strikes):
        raise PlanError("a strike is listed twice")
    before = [s for s in strikes if s in BEFORE_HARDEN]
    if before and len(before) != len(strikes):
        raise PlanError("plan the strikes (S*) and the after-harden attempts (D-*) separately")
    ordered = tuple(s for s in (*BEFORE_HARDEN, *AFTER_HARDEN) if s in strikes)
    t = lab_targets(manifest)
    run_id = run_id or new_run_id(now)
    pre = read_pre_state(ordered, t, reader)
    expires = min(now + PLAN_LIFETIME, manifest.expires_at)
    if manifest.strike is not None:
        expires = min(expires, manifest.strike.expires_at)
    return StrikePlan(
        run_id=run_id,
        tenant_id=str(manifest.tenant_id).lower(),
        scope_sha256=scope_sha256,
        agent_object_id=t.agent,
        created_at=now,
        expires_at=expires,
        strikes=ordered,
        targets=t.as_dict(),
        pre_state=pre,
        writes=planned_writes(ordered, t, pre, run_id, now),
    )
