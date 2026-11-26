"""Principal closure: everything an assumed-compromised identity can become.

Facts are seeded from the snapshot, plus ``controls(<compromised>)``. Escalation
rules then run in rounds to a fixed point. Every fact keeps the first derivation
that produced it (the earliest round), so unwinding premises gives a shortest
justification. Rounds only read facts from earlier rounds, which makes the
result independent of rule order.

Fact kinds:

- ``controls(P)``: the attacker can act as principal P.
- ``member(P, G)``: P is (transitively) in group G; G's grants apply to P.
- ``app-perm(P, value)``: P holds a Microsoft Graph application permission.
- ``dir-role(P, role, scope)``: P holds a directory role at a directory scope.
- ``rbac(P, scope, roleDefinition, assignment, condition)``: an Azure RBAC grant.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Final, Literal

from fns.contain import rbac
from fns.contain import semantics as sem
from fns.fixtures import wellknown as wk
from fns.models.armid import ArmIdError, parse_arm_id
from fns.models.snapshot import (
    TENANT_ROOT_SCOPE,
    DenyAssignment,
    Entity,
    HasAccessPolicy,
    HasAppRole,
    HasDirectoryRole,
    HasEligibleRole,
    HasIdentity,
    HasRbacRole,
    InstanceOf,
    MemberOf,
    Owns,
    Snapshot,
)

FactKind = Literal["controls", "member", "app-perm", "dir-role", "rbac"]

APP_ADMIN_ROLES: Final = frozenset(
    {wk.GLOBAL_ADMINISTRATOR, wk.APPLICATION_ADMINISTRATOR, wk.CLOUD_APPLICATION_ADMINISTRATOR}
)
ROLE_ADMIN_ROLES: Final = frozenset({wk.PRIVILEGED_ROLE_ADMINISTRATOR})

RUN_AS: Final[dict[str, str]] = {
    "microsoft.compute/virtualmachines": "Microsoft.Compute/virtualMachines/runCommand/action",
    "microsoft.automation/automationaccounts": "Microsoft.Automation/automationAccounts/jobs/write",
}
"""Resource types whose code-execution action lets a caller act as the resource's
managed identity. Other compute (App Service, Functions, containers) is not
modeled in M2."""


@dataclass(frozen=True, order=True, slots=True)
class Fact:
    kind: FactKind
    principal: str
    args: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Derivation:
    fact: Fact
    rule: str
    premises: tuple[Fact, ...]
    sources: tuple[str, ...]
    text: str
    depth: int


@dataclass(frozen=True, slots=True)
class _Candidate:
    fact: Fact
    rule: str
    premises: tuple[Fact, ...]
    sources: tuple[str, ...]
    text: str


def controls(p: str) -> Fact:
    return Fact("controls", p)


def app_perm(p: str, value: str) -> Fact:
    return Fact("app-perm", p, (value,))


class SnapshotIndex:
    """Lookups over one snapshot. Built once; read-only afterwards."""

    def __init__(self, snapshot: Snapshot) -> None:
        self.snapshot = snapshot
        self.entities: dict[str, Entity] = {e.id: e for e in snapshot.entities}
        self.role_defs: dict[str, rbac.RoleDefinition] = {
            e.id: rbac.RoleDefinition.from_entity(e)
            for e in snapshot.entities
            if e.type == "roleDefinition"
        }
        self.graph_sps = frozenset(
            e.id
            for e in snapshot.entities
            if e.type == "servicePrincipal"
            and str(e.properties.get("appId", "")).lower() == wk.MICROSOFT_GRAPH_APP_ID
        )
        self.owns: dict[str, list[Owns]] = defaultdict(list)
        self.member_of: dict[str, list[MemberOf]] = defaultdict(list)
        self.sps_of_app: dict[str, list[InstanceOf]] = defaultdict(list)
        self.identities_of: dict[str, list[HasIdentity]] = defaultdict(list)
        self.app_roles: list[HasAppRole] = []
        self.dir_roles: list[HasDirectoryRole] = []
        self.rbac_roles: list[HasRbacRole] = []
        self.denies: list[DenyAssignment] = []
        self.access_policies: dict[str, list[HasAccessPolicy]] = defaultdict(list)
        for edge in snapshot.edges:
            if isinstance(edge, Owns):
                self.owns[edge.src].append(edge)
            elif isinstance(edge, MemberOf):
                self.member_of[edge.src].append(edge)
            elif isinstance(edge, InstanceOf):
                self.sps_of_app[edge.dst].append(edge)
            elif isinstance(edge, HasIdentity):
                self.identities_of[edge.src].append(edge)
            elif isinstance(edge, HasAppRole):
                self.app_roles.append(edge)
            elif isinstance(edge, HasDirectoryRole):
                self.dir_roles.append(edge)
            elif isinstance(edge, HasRbacRole):
                self.rbac_roles.append(edge)
            elif isinstance(edge, DenyAssignment):
                self.denies.append(edge)
            elif isinstance(edge, HasAccessPolicy):
                self.access_policies[edge.dst].append(edge)

    def name(self, entity_id: str) -> str:
        e = self.entities.get(entity_id)
        if e is None or not e.display_name:
            return entity_id
        return e.display_name

    def type_of(self, entity_id: str) -> str | None:
        e = self.entities.get(entity_id)
        return e.type if e is not None else None

    def source(self, edge: object) -> str:
        src, dst = getattr(edge, "src"), getattr(edge, "dst")  # noqa: B009
        kind = getattr(edge, "type")  # noqa: B009
        api = getattr(edge, "provenance").source_api  # noqa: B009
        return f"{kind}: {self.name(src)} -> {self.name(dst)} [{api}]"

    def graph_role_value(self, edge: HasAppRole) -> str | None:
        if edge.app_role_value:
            return edge.app_role_value
        sp = self.entities.get(edge.dst)
        roles = sp.properties.get("appRoles") if sp is not None else None
        if isinstance(roles, tuple):
            for item in roles:
                rid, _, value = item.partition("=")
                if rid.lower() == str(edge.app_role_id):
                    return value
        return None

    def denied(self, principals: frozenset[str], action: str, *, data: bool, at: str) -> bool:
        return any(
            rbac.deny_applies(d, principals, action, data=data, at_scope=at) for d in self.denies
        )


class Closure:
    """Facts derivable from a snapshot once ``compromised`` is assumed controlled."""

    def __init__(
        self, index: SnapshotIndex, compromised: str, rules: tuple[Rule, ...] | None = None
    ) -> None:
        self.index = index
        self.compromised = compromised
        self.derivations: dict[Fact, Derivation] = {}
        self.uncertain: set[str] = set()
        """Things that could add reach but the model cannot decide (conditions,
        missing role definitions, unresolved app role IDs)."""
        self._seed()
        self._run(rules if rules is not None else RULES)
        self.eligibility: tuple[str, ...] = self._eligibility()
        """PIM eligibility of anything the attacker controls (M3 E1). Activation is
        not modeled, so each one leaves every finding open."""
        self.uncertain.update(self.eligibility)

    def _eligibility(self) -> tuple[str, ...]:
        ix = self.index
        holders = {p for c in self.controlled() for p in self.effective(c)}
        out = set()
        for e in ix.snapshot.edges:
            if isinstance(e, HasEligibleRole) and e.src in holders:
                where = (
                    f"directory scope {e.directory_scope_id or '/'}"
                    if e.plane == "directory"
                    else ix.name(e.dst)
                )
                role = ix.name(e.role_definition_id)
                if role == e.role_definition_id:
                    role = f"role {role.rsplit('/', 1)[-1]}"
                out.add(
                    f"{ix.name(e.src)} is eligible (PIM) for {role} at {where}; "
                    "activation is not modeled"
                )
        return tuple(sorted(out))

    # -- queries -----------------------------------------------------------

    def has(self, fact: Fact) -> bool:
        return fact in self.derivations

    def controlled(self) -> list[str]:
        return sorted(f.principal for f in self.derivations if f.kind == "controls")

    def effective(self, principal: str) -> frozenset[str]:
        groups = {
            f.args[0] for f in self.derivations if f.kind == "member" and f.principal == principal
        }
        return frozenset({principal, *groups})

    def membership(self, principal: str, holder: str) -> tuple[Fact, ...]:
        """The premise that makes ``holder``'s grants apply to ``principal``."""
        if holder == principal:
            return ()
        return (Fact("member", principal, (holder,)),)

    def facts_of(self, kind: FactKind, principals: frozenset[str]) -> list[Fact]:
        return sorted(f for f in self.derivations if f.kind == kind and f.principal in principals)

    def app_perms(self, principal: str) -> set[str]:
        return {
            f.args[0] for f in self.derivations if f.kind == "app-perm" and f.principal == principal
        }

    def role(self, grant: Fact) -> rbac.RoleDefinition | None:
        role_id = grant.args[1]
        if role_id == rbac.ANY_ROLE:
            return rbac.ANY
        return self.index.role_defs.get(role_id)

    # -- seeding -----------------------------------------------------------

    def _add(self, c: _Candidate, depth: int) -> None:
        self.derivations[c.fact] = Derivation(c.fact, c.rule, c.premises, c.sources, c.text, depth)

    def _seed(self) -> None:
        ix = self.index
        n = ix.name
        seeds: list[_Candidate] = [
            _Candidate(
                controls(self.compromised),
                "assume-compromised",
                (),
                (),
                f"assume {n(self.compromised)} is compromised",
            )
        ]
        for a in ix.app_roles:
            if a.dst not in ix.graph_sps:
                continue
            value = ix.graph_role_value(a)
            if value is None:
                self.uncertain.add(f"Graph app role {a.app_role_id} of {n(a.src)} is unresolved")
                continue
            seeds.append(
                _Candidate(
                    app_perm(a.src, value),
                    "snapshot",
                    (),
                    (ix.source(a),),
                    f"{n(a.src)} holds the Graph permission {value}",
                )
            )
        for d in ix.dir_roles:
            seeds.append(
                _Candidate(
                    Fact("dir-role", d.src, (d.dst, d.directory_scope_id)),
                    "snapshot",
                    (),
                    (ix.source(d),),
                    f"{n(d.src)} has the directory role {n(d.dst)} at {d.directory_scope_id}",
                )
            )
        for r in ix.rbac_roles:
            role = ix.role_defs.get(r.role_definition_id)
            role_name = role.name if role is not None else r.role_definition_id
            seeds.append(
                _Candidate(
                    Fact(
                        "rbac",
                        r.src,
                        (r.dst, r.role_definition_id, r.assignment_id, r.condition or ""),
                    ),
                    "snapshot",
                    (),
                    (ix.source(r),),
                    f"{n(r.src)} has {role_name} at {_scope_name(ix, r.dst)}",
                )
            )
        for c in sorted(seeds, key=lambda c: c.fact):
            if c.fact not in self.derivations:
                self._add(c, 0)

    # -- fixed point -------------------------------------------------------

    def _run(self, rules: tuple[Rule, ...]) -> None:
        depth = 0
        while True:
            depth += 1
            new: dict[Fact, _Candidate] = {}
            for rule in rules:
                for cand in rule(self):
                    if cand.fact not in self.derivations and cand.fact not in new:
                        new[cand.fact] = cand
            if not new:
                return
            for fact in sorted(new):
                self._add(new[fact], depth)


Rule = Callable[[Closure], Iterator[_Candidate]]


def _scope_name(ix: SnapshotIndex, scope: str) -> str:
    e = ix.entities.get(scope)
    if e is not None and e.display_name:
        return e.display_name
    return scope_label(scope)


def scope_label(scope: str) -> str:
    """``resource group rg-fns-lab`` rather than the full ID, for path text."""
    if scope == TENANT_ROOT_SCOPE:
        return "the root scope /"
    try:
        path = parse_arm_id(scope)
    except ArmIdError:
        return scope
    if path.level == "managementGroup":
        return f"management group {path.management_group}"
    if path.level == "subscription":
        return f"subscription {path.subscription_id}"
    if path.level == "resourceGroup":
        return f"resource group {path.resource_group}"
    return scope.rsplit("/", 1)[-1]


def _rule_member_of(c: Closure) -> Iterator[_Candidate]:
    ix = c.index
    for p in c.controlled():
        for holder in sorted(c.effective(p)):
            for edge in ix.member_of.get(holder, ()):
                yield _Candidate(
                    Fact("member", p, (edge.dst,)),
                    "member-of",
                    (controls(p), *c.membership(p, holder)),
                    (ix.source(edge),),
                    f"{ix.name(p)} is in the group {ix.name(edge.dst)}; its grants apply",
                )


def _sps_of(ix: SnapshotIndex, obj: str) -> list[tuple[str, tuple[str, ...]]]:
    """Service principals a credential on ``obj`` lets you sign in as."""
    if ix.type_of(obj) == "servicePrincipal":
        return [(obj, ())]
    return [(e.src, (ix.source(e),)) for e in ix.sps_of_app.get(obj, ())]


def _rule_owner_adds_credential(c: Closure) -> Iterator[_Candidate]:
    ix = c.index
    for p in c.controlled():
        perms = sorted(c.app_perms(p) & {sem.APP_READWRITE_OWNEDBY, sem.APP_READWRITE_ALL})
        if not perms:
            continue
        perm = sem.APP_READWRITE_OWNEDBY if sem.APP_READWRITE_OWNEDBY in perms else perms[0]
        for edge in ix.owns.get(p, ()):
            for sp, extra in _sps_of(ix, edge.dst):
                if sp == p:
                    continue
                yield _Candidate(
                    controls(sp),
                    "owner-adds-credential",
                    (controls(p), app_perm(p, perm)),
                    (ix.source(edge), *extra),
                    f"{ix.name(p)} owns {ix.name(edge.dst)}; with {perm} it adds a "
                    f"credential and signs in as {ix.name(sp)}",
                )


def _all_tenant_sps(ix: SnapshotIndex) -> list[tuple[str, tuple[str, ...]]]:
    out: list[tuple[str, tuple[str, ...]]] = []
    for app in sorted(ix.sps_of_app):
        out.extend(_sps_of(ix, app))
    return sorted(out)


def _rule_app_readwrite_all(c: Closure) -> Iterator[_Candidate]:
    ix = c.index
    for p in c.controlled():
        if sem.APP_READWRITE_ALL not in c.app_perms(p):
            continue
        for sp, extra in _all_tenant_sps(ix):
            if sp != p:
                yield _Candidate(
                    controls(sp),
                    "app-readwrite-all",
                    (controls(p), app_perm(p, sem.APP_READWRITE_ALL)),
                    extra,
                    f"with {sem.APP_READWRITE_ALL}, {ix.name(p)} adds a credential to "
                    f"{ix.name(sp)}'s application and signs in as it",
                )


def _rule_app_admin_role(c: Closure) -> Iterator[_Candidate]:
    ix = c.index
    for p in c.controlled():
        for f in c.facts_of("dir-role", c.effective(p)):
            role, scope = f.args
            if role not in APP_ADMIN_ROLES:
                continue
            scoped = scope.strip("/").lower()
            targets = _all_tenant_sps(ix) if scope == "/" else _sps_of(ix, scoped)
            for sp, extra in targets:
                if sp != p:
                    yield _Candidate(
                        controls(sp),
                        "app-admin-role",
                        (controls(p), *c.membership(p, f.principal), f),
                        extra,
                        f"as {ix.name(role)}, {ix.name(p)} adds a credential to "
                        f"{ix.name(sp)}'s application and signs in as it",
                    )


def _rule_approle_self_grant(c: Closure) -> Iterator[_Candidate]:
    ix = c.index
    wanted = sorted(sem.graph_permissions_in_use())
    controlled = c.controlled()
    for p in controlled:
        if sem.APPROLE_READWRITE_ALL not in c.app_perms(p):
            continue
        for q in controlled:
            for value in wanted:
                yield _Candidate(
                    app_perm(q, value),
                    "approle-self-grant",
                    (controls(p), app_perm(p, sem.APPROLE_READWRITE_ALL), controls(q)),
                    (),
                    f"with {sem.APPROLE_READWRITE_ALL}, {ix.name(p)} grants "
                    f"{ix.name(q)} the Graph permission {value}",
                )


def _rule_rolemanagement_write(c: Closure) -> Iterator[_Candidate]:
    ix = c.index
    ga = wk.GLOBAL_ADMINISTRATOR
    for p in c.controlled():
        target = Fact("dir-role", p, (ga, "/"))
        if sem.ROLEMANAGEMENT_READWRITE in c.app_perms(p):
            yield _Candidate(
                target,
                "rolemanagement-write",
                (controls(p), app_perm(p, sem.ROLEMANAGEMENT_READWRITE)),
                (),
                f"with {sem.ROLEMANAGEMENT_READWRITE}, {ix.name(p)} assigns itself {ix.name(ga)}",
            )
        for f in c.facts_of("dir-role", c.effective(p)):
            if f.args[0] in ROLE_ADMIN_ROLES and f.args[1] == "/":
                yield _Candidate(
                    target,
                    "rolemanagement-write",
                    (controls(p), *c.membership(p, f.principal), f),
                    (),
                    f"as {ix.name(f.args[0])}, {ix.name(p)} assigns itself {ix.name(ga)}",
                )


def _rule_rbac_write(c: Closure) -> Iterator[_Candidate]:
    ix = c.index
    for p in c.controlled():
        eff = c.effective(p)
        for g in c.facts_of("rbac", eff):
            scope, role_id, _assignment, condition = g.args
            if role_id == rbac.ANY_ROLE:
                continue
            role = c.role(g)
            if role is None:
                c.uncertain.add(f"role definition {role_id} was not collected")
                continue
            if not role.permits(sem.ROLE_ASSIGNMENTS_WRITE, data=False):
                continue
            if ix.denied(eff, sem.ROLE_ASSIGNMENTS_WRITE, data=False, at=scope):
                continue
            if condition:
                c.uncertain.add(
                    f"{ix.name(g.principal)}'s {role.name} at {_scope_name(ix, scope)} has an "
                    "ABAC condition on roleAssignments/write (not evaluated)"
                )
                continue
            yield _Candidate(
                Fact("rbac", p, (scope, rbac.ANY_ROLE, f"rbac-write:{scope}", "")),
                "rbac-write",
                (controls(p), *c.membership(p, g.principal), g),
                (),
                f"with roleAssignments/write from {role.name}, {ix.name(p)} assigns itself "
                f"any role at {_scope_name(ix, scope)}",
            )


def _rule_managed_identity(c: Closure) -> Iterator[_Candidate]:
    ix = c.index
    for resource_id in sorted(ix.identities_of):
        entity = ix.entities.get(resource_id)
        rtype = str(entity.properties.get("resourceType", "")).lower() if entity else ""
        action = RUN_AS.get(rtype)
        if action is None:
            continue
        for p in c.controlled():
            eff = c.effective(p)
            for g in c.facts_of("rbac", eff):
                rel = rbac.scope_relation(g.args[0], resource_id)
                role = c.role(g)
                if rel not in {"self", "ancestor"} or role is None or g.args[3]:
                    continue
                if not role.permits(action, data=False) or ix.denied(
                    eff, action, data=False, at=resource_id
                ):
                    continue
                for edge in ix.identities_of[resource_id]:
                    yield _Candidate(
                        controls(edge.dst),
                        "managed-identity",
                        (controls(p), *c.membership(p, g.principal), g),
                        (ix.source(edge),),
                        f"{ix.name(p)} runs code on {ix.name(resource_id)} ({action}) and "
                        f"acts as its managed identity",
                    )


RULES: Final[tuple[Rule, ...]] = (
    _rule_member_of,
    _rule_owner_adds_credential,
    _rule_app_readwrite_all,
    _rule_app_admin_role,
    _rule_approle_self_grant,
    _rule_rolemanagement_write,
    _rule_rbac_write,
    _rule_managed_identity,
)
