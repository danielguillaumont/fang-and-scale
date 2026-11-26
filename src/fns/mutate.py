"""Defence mutation testing (PLAN section 5.3, M5).

Five operators weaken the baseline the way a careless change would: Owner at a
resource group, listKeys on a storage account, a privileged Microsoft Graph
application permission, ownership of another application, and removal of a deny
assignment. Each mutant is applied to the snapshot model and, where the lab
Terraform has the addresses, rendered as a diff against ``lab/``. The contract
must notice every one: a mutant is killed when evaluation gains a failing
finding. Nothing is applied anywhere; every result is rung ``modeled``.
"""

from __future__ import annotations

import difflib
import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from fns.contain.evaluate import Evaluation, evaluate
from fns.contain.resolve import resolve_identity
from fns.fixtures import wellknown as wk
from fns.harden.minimize import NoProposalError, edited_files, minimize
from fns.harden.tfmap import (
    Block,
    LabMap,
    TfParseError,
    _Resolver,
    apply_to_snapshot,
    map_lab,
    parse_lines,
)
from fns.models.contract import Contract
from fns.models.mutation import (
    OPERATORS,
    MutantResult,
    MutationReport,
    NotApplicable,
    Operator,
    OperatorScore,
    Outcome,
)
from fns.models.snapshot import DenyAssignment, Entity, HasAppRole, HasRbacRole, Owns, Snapshot

PROVENANCE: Final = "fns:mutation"
STORAGE_KEY_OPERATOR: Final = wk.STORAGE_ACCOUNT_KEY_OPERATOR
ROLE_DEFINITIONS: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    wk.OWNER: ("Owner", ("*",)),
    STORAGE_KEY_OPERATOR: (
        "Storage Account Key Operator Service Role",
        (
            "Microsoft.Storage/storageAccounts/listkeys/action",
            "Microsoft.Storage/storageAccounts/regeneratekey/action",
        ),
    ),
}
GRAPH_PERMISSIONS: Final[tuple[tuple[str, str], ...]] = (
    ("AppRoleAssignment.ReadWrite.All", wk.APPROLEASSIGNMENT_READWRITE_ALL),
    ("Application.ReadWrite.All", wk.APPLICATION_READWRITE_ALL),
    ("RoleManagement.ReadWrite.Directory", wk.ROLEMANAGEMENT_READWRITE_DIRECTORY),
)


class MutateError(ValueError):
    pass


@dataclass(frozen=True)
class Mutant:
    id: str
    operator: Operator
    description: str
    add_entities: tuple[dict[str, Any], ...] = ()
    add_edges: tuple[dict[str, Any], ...] = ()
    remove_deny: str | None = None
    terraform_file: str | None = None
    terraform_lines: tuple[str, ...] | None = None
    """The whole edited file, or None when Terraform cannot express the mutant."""
    terraform_note: str | None = None


@dataclass
class _Context:
    contract: Contract
    snapshot: Snapshot
    principal: Entity
    refs: dict[str, str]
    """Snapshot entity id -> Terraform expression."""
    blocks: dict[str, Block]
    files: dict[str, list[str]]
    graph_data: str | None
    entities: dict[str, Entity] = field(default_factory=dict)


def _guid(seed: str) -> str:
    return str(uuid.UUID(bytes=hashlib.sha256(seed.encode()).digest()[:16], version=4))


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _subscription(entity_id: str) -> str | None:
    m = re.match(r"^/subscriptions/([^/]+)", entity_id)
    return m.group(1) if m else None


def _reverse_refs(blocks: dict[str, Block], snapshot: Snapshot) -> dict[str, str]:
    r = _Resolver(blocks, snapshot)
    refs: dict[str, str] = {}
    for b in sorted(blocks.values(), key=lambda b: b.address):
        if b.kind != "resource":
            continue
        try:
            if b.type == "azuread_service_principal":
                refs.setdefault(r.principal(f"{b.address}.object_id").id, f"{b.address}.object_id")
            elif b.type == "azuread_application":
                refs.setdefault(r.application(b).id, b.address)
            elif b.type in {
                "azurerm_resource_group",
                "azurerm_storage_account",
                "azurerm_key_vault",
            }:
                refs.setdefault(r.named(b.address).id, f"{b.address}.id")
        except LookupError:
            continue
    return refs


def _edge(kind: str, src: str, dst: str, snapshot: Snapshot, **extra: Any) -> dict[str, Any]:
    return {
        "type": kind,
        "src": src,
        "dst": dst,
        "provenance": {"source_api": PROVENANCE, "observed_at": snapshot.collected_at.isoformat()},
        **extra,
    }


def _rbac(ctx: _Context, op: Operator, guid: str, scope: Entity, what: str) -> Mutant:
    name, actions = ROLE_DEFINITIONS[guid]
    sub = _subscription(scope.id)
    if sub is None:
        raise MutateError(f"{scope.id} is not under a subscription")
    role_id = f"/subscriptions/{sub}/providers/microsoft.authorization/roledefinitions/{guid}"
    mid = f"{op}:{scope.display_name or scope.id.rsplit('/', 1)[-1]}"
    entities: list[dict[str, Any]] = []
    if role_id not in ctx.entities:
        entities.append(
            {
                "id": role_id,
                "type": "roleDefinition",
                "display_name": name,
                "properties": {
                    "actions": list(actions),
                    "notActions": [],
                    "dataActions": [],
                    "notDataActions": [],
                    "roleType": "BuiltInRole",
                },
            }
        )
    edge = _edge(
        "hasRbacRole",
        ctx.principal.id,
        scope.id,
        ctx.snapshot,
        role_definition_id=role_id,
        assignment_id=f"{scope.id}/providers/microsoft.authorization/roleassignments/{_guid(mid)}",
    )
    who, where = ctx.refs.get(ctx.principal.id), ctx.refs.get(scope.id)
    lines = None
    note = None
    file = "resources.tf"
    if who and where and file in ctx.files:
        lines = (
            *ctx.files[file],
            "",
            f'resource "azurerm_role_assignment" "mutant_{_slug(mid)}" {{',
            f"  scope                = {where}",
            f'  role_definition_name = "{name}"',
            f"  principal_id         = {who}",
            '  principal_type       = "ServicePrincipal"',
            f'  description          = "fns mutant {mid}"',
            "}",
        )
    else:
        note = "no lab Terraform address for the principal or the scope"
    return Mutant(
        mid,
        op,
        f"grant {name} to {ctx.principal.display_name} on {what}",
        tuple(entities),
        (edge,),
        terraform_file=file if lines else None,
        terraform_lines=lines,
        terraform_note=note,
    )


def _held(ctx: _Context, pred: Any) -> bool:
    return any(e.src == ctx.principal.id and pred(e) for e in ctx.snapshot.edges)


def _mutants(ctx: _Context) -> tuple[list[Mutant], list[NotApplicable]]:
    out: list[Mutant] = []
    na: list[NotApplicable] = []
    snap = ctx.snapshot
    names = {e.id: (e.display_name or "") for e in snap.entities}

    def holds_role(guid: str, scope_id: str) -> bool:
        return _held(
            ctx,
            lambda e: (
                isinstance(e, HasRbacRole)
                and e.dst == scope_id
                and e.role_definition_id.endswith(f"/{guid}")
            ),
        )

    rgs = [e for e in snap.entities if e.type == "scope" and e.id.count("/") == 4]
    for rg in sorted(rgs, key=lambda e: e.id):
        if holds_role(wk.OWNER, rg.id):
            na.append(NotApplicable(operator="owner-at-rg", reason=f"already Owner on {rg.id}"))
            continue
        rg_named = Entity(
            id=rg.id, type=rg.type, display_name=rg.id.rsplit("/", 1)[-1], properties={}
        )
        out.append(
            _rbac(ctx, "owner-at-rg", wk.OWNER, rg_named, f"resource group {rg_named.display_name}")
        )
    if not rgs:
        na.append(NotApplicable(operator="owner-at-rg", reason="no resource group in the snapshot"))

    accounts = [
        e
        for e in snap.entities
        if e.type == "resource"
        and str(e.properties.get("resourceType", "")).lower() == "microsoft.storage/storageaccounts"
    ]
    for acct in sorted(accounts, key=lambda e: e.id):
        if holds_role(STORAGE_KEY_OPERATOR, acct.id):
            continue
        out.append(
            _rbac(
                ctx, "listkeys", STORAGE_KEY_OPERATOR, acct, f"storage account {acct.display_name}"
            )
        )
    if not accounts:
        na.append(NotApplicable(operator="listkeys", reason="no storage account in the snapshot"))

    graph = [
        e
        for e in snap.entities
        if e.type == "servicePrincipal" and e.properties.get("appId") == wk.MICROSOFT_GRAPH_APP_ID
    ]
    if not graph:
        na.append(
            NotApplicable(
                operator="graph-app-permission", reason="Microsoft Graph not in the snapshot"
            )
        )
    for value, role_guid in GRAPH_PERMISSIONS if graph else ():
        if _held(ctx, lambda e, v=value: isinstance(e, HasAppRole) and e.app_role_value == v):
            na.append(
                NotApplicable(operator="graph-app-permission", reason=f"{value} is already held")
            )
            continue
        mid = f"graph-app-permission:{value}"
        who = ctx.refs.get(ctx.principal.id)
        lines = None
        if who and ctx.graph_data and "identities.tf" in ctx.files:
            lines = (
                *ctx.files["identities.tf"],
                "",
                f'resource "azuread_app_role_assignment" "mutant_{_slug(value)}" {{',
                f'  app_role_id         = local.graph_roles["{value}"]',
                f"  principal_object_id = {who}",
                f"  resource_object_id  = {ctx.graph_data}.object_id",
                "}",
            )
        out.append(
            Mutant(
                mid,
                "graph-app-permission",
                f"grant Graph {value} to {ctx.principal.display_name}",
                (),
                (
                    _edge(
                        "hasAppRole",
                        ctx.principal.id,
                        graph[0].id,
                        snap,
                        app_role_id=role_guid,
                        app_role_value=value,
                        assignment_id=f"mutant-{_guid(mid)}",
                    ),
                ),
                terraform_file="identities.tf" if lines else None,
                terraform_lines=lines,
                terraform_note=None
                if lines
                else "no lab Terraform address for the principal or Graph",
            )
        )

    own_apps = {e.dst for e in snap.edges if e.type == "instanceOf" and e.src == ctx.principal.id}
    owned = {e.dst for e in snap.edges if isinstance(e, Owns) and e.src == ctx.principal.id}
    apps = [e for e in snap.entities if e.type == "application"]
    for app in sorted(apps, key=lambda e: (e.display_name or "", e.id)):
        if app.id in own_apps or app.id in owned:
            continue
        mid = f"app-owner:{app.display_name or app.id}"
        who, addr = ctx.refs.get(ctx.principal.id), ctx.refs.get(app.id)
        lines = None
        file = None
        if who and addr and addr in ctx.blocks and "owners" in ctx.blocks[addr].attr_lines:
            block = ctx.blocks[addr]
            file = block.file
            i = block.attr_lines["owners"]
            current = ctx.files[file][i]
            key, _, value = current.partition("=")
            edited = list(ctx.files[file])
            edited[i] = f"{key}= concat({value.strip()}, [{who}])"
            lines = tuple(edited)
        out.append(
            Mutant(
                mid,
                "app-owner",
                f"make {ctx.principal.display_name} an owner of {app.display_name}",
                (),
                (_edge("owns", ctx.principal.id, app.id, snap),),
                terraform_file=file,
                terraform_lines=lines,
                terraform_note=None if lines else "no lab Terraform block with owners for this app",
            )
        )
    if not any(m.operator == "app-owner" for m in out):
        na.append(
            NotApplicable(operator="app-owner", reason="no other application to become owner of")
        )

    denies = sorted(
        (e for e in snap.edges if isinstance(e, DenyAssignment)), key=lambda e: e.deny_assignment_id
    )
    for d in denies:
        out.append(
            Mutant(
                f"remove-deny-assignment:{d.deny_assignment_id.rsplit('/', 1)[-1]}",
                "remove-deny-assignment",
                f"remove deny assignment {d.deny_assignment_id} on {names.get(d.dst) or d.dst}",
                remove_deny=d.deny_assignment_id,
                terraform_note="deny assignments are created by Azure (managed apps, deployment "
                "stacks), not by azurerm resources",
            )
        )
    if not denies:
        na.append(
            NotApplicable(
                operator="remove-deny-assignment", reason="no deny assignment in the snapshot"
            )
        )
    return out, na


def apply_mutant(snapshot: Snapshot, m: Mutant) -> Snapshot:
    data = snapshot.model_dump(mode="json")
    data["entities"] = [*data["entities"], *m.add_entities]
    edges = [*data["edges"], *m.add_edges]
    if m.remove_deny is not None:
        edges = [
            e
            for e in edges
            if not (e["type"] == "denyAssignment" and e["deny_assignment_id"] == m.remove_deny)
        ]
    data["edges"] = edges
    return Snapshot.model_validate(data)


def _labels(ev: Evaluation, verdict: str) -> dict[str, str]:
    return {
        o.finding.id: f"{o.finding.target} {o.finding.operation}"
        for o in ev.outcomes
        if o.finding.verdict == verdict
    }


def _diff(old: list[str], new: tuple[str, ...], name: str) -> str:
    return "".join(
        difflib.unified_diff(
            [f"{line}\n" for line in old],
            [f"{line}\n" for line in new],
            fromfile=f"a/lab/{name}",
            tofile=f"b/lab/{name}",
        )
    )


@dataclass(frozen=True)
class Prepared:
    baseline: Snapshot
    hardened_with: tuple[str, ...]
    files: dict[str, list[str]]
    """Lab ``*.tf`` text after hardening (empty without a lab directory)."""
    mutants: tuple[Mutant, ...]
    not_applicable: tuple[NotApplicable, ...]


def prepare(
    contract: Contract, snapshot: Snapshot, lab_dir: Path | None, *, harden: bool
) -> Prepared:
    """The baseline (hardened in the model if asked) and every mutant of it."""
    who = resolve_identity(snapshot, contract.assume_compromised)
    if who.entity is None:
        raise MutateError(f"cannot mutate: {who.reason}")
    blocks: dict[str, Block] = {}
    files: dict[str, list[str]] = {}
    lab: LabMap | None = None
    if lab_dir is not None and lab_dir.is_dir():
        try:
            lab = map_lab(lab_dir, snapshot)
        except TfParseError as exc:
            raise MutateError(f"cannot read {lab_dir}: {exc}") from exc
        blocks = lab.blocks
        files = {
            p.name: p.read_text(encoding="utf-8").splitlines() for p in sorted(lab_dir.glob("*.tf"))
        }
    baseline = snapshot
    hardened: tuple[str, ...] = ()
    if harden:
        if lab is None or lab_dir is None:
            raise MutateError("--harden needs the lab Terraform directory")
        try:
            proposal = minimize(contract, snapshot, lab_dir, lab=lab)
        except NoProposalError as exc:
            raise MutateError(f"cannot harden first: {exc}") from exc
        baseline = apply_to_snapshot(snapshot, proposal.levers)
        hardened = tuple(lv.address for lv in proposal.levers)
        for name, (_, new) in edited_files(lab_dir, lab, proposal.levers).items():
            files[name] = new
        # Blocks moved or vanished; re-read them from the hardened text.
        blocks = {b.address: b for name, lines in files.items() for b in parse_lines(name, lines)}
    graph_data = next(
        (
            b.address
            for b in blocks.values()
            if b.kind == "data"
            and b.type == "azuread_service_principal"
            and wk.MICROSOFT_GRAPH_APP_ID in b.attrs.get("client_id", "")
        ),
        None,
    )
    ctx = _Context(
        contract,
        baseline,
        who.entity,
        _reverse_refs(blocks, baseline) if blocks else {},
        blocks,
        files,
        graph_data,
        {e.id: e for e in baseline.entities},
    )
    mutants, na = _mutants(ctx)
    return Prepared(
        baseline,
        hardened,
        files,
        tuple(sorted(mutants, key=lambda m: (OPERATORS.index(m.operator), m.id))),
        tuple(sorted(na, key=lambda n: (OPERATORS.index(n.operator), n.reason))),
    )


def mutate(
    contract: Contract,
    snapshot: Snapshot,
    lab_dir: Path | None,
    *,
    harden: bool,
    generated_at: datetime,
    tool_version: str,
) -> MutationReport:
    prep = prepare(contract, snapshot, lab_dir, harden=harden)
    baseline, files = prep.baseline, prep.files
    base_eval = evaluate(contract, baseline)
    base_fail = _labels(base_eval, "fail")
    base_inc = _labels(base_eval, "inconclusive")
    results: list[MutantResult] = []
    for m in prep.mutants:
        ev = evaluate(contract, apply_mutant(baseline, m))
        new_fail = sorted(v for k, v in _labels(ev, "fail").items() if k not in base_fail)
        new_inc = sorted(v for k, v in _labels(ev, "inconclusive").items() if k not in base_inc)
        outcome: Outcome
        if new_fail:
            outcome = "killed"
        elif new_inc:
            outcome = "inconclusive"
        else:
            outcome = "survived"
        diff = (
            _diff(files[m.terraform_file], m.terraform_lines, m.terraform_file)
            if m.terraform_file and m.terraform_lines is not None
            else None
        )
        results.append(
            MutantResult(
                id=m.id,
                operator=m.operator,
                description=m.description,
                outcome=outcome,
                new_failures=tuple(new_fail),
                new_inconclusive=tuple(new_inc),
                terraform_file=m.terraform_file if diff else None,
                terraform_diff=diff,
                terraform_note=None if diff else (m.terraform_note or "no Terraform"),
            )
        )
    by_op = tuple(
        OperatorScore(
            operator=op,
            killed=sum(r.outcome == "killed" for r in results if r.operator == op),
            total=sum(r.operator == op for r in results),
        )
        for op in OPERATORS
    )
    return MutationReport(
        version=1,
        mode=snapshot.mode,
        contract=contract.contract,
        contract_digest=contract.digest(),
        snapshot_digest=snapshot.digest(),
        hardened_with=prep.hardened_with,
        baseline_exit_code=base_eval.summary.exit_code,
        baseline_failures=len(base_fail),
        baseline_inconclusive=len(base_inc),
        killed=sum(r.outcome == "killed" for r in results),
        total=len(results),
        by_operator=by_op,
        mutants=tuple(results),
        not_applicable=prep.not_applicable,
        generated_at=generated_at,
        tool_version=tool_version,
    )
