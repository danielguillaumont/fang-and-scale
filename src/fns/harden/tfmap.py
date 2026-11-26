"""Map the lab's Terraform to the snapshot: which blocks grant what, and how to cut them.

Not a general HCL parser. It reads top-level ``resource`` / ``data`` blocks with
brace matching (strings and ``${...}`` respected) and single-line top-level
attributes, which is all the lab uses. A construct it does not understand
makes the lever ``unmapped``; it is never guessed (docs/milestones/M4.md, H2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

from fns.models.snapshot import Entity, HasAppRole, HasRbacRole, Owns, Snapshot

LeverKind = Literal["rbac", "app-role", "owner", "shared-key"]

_BLOCK_RE: Final = re.compile(r'^(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{\s*$')
_ATTR_RE: Final = re.compile(r"^  ([a-z_][a-z0-9_]*)\s*=\s*(.+?)\s*$")
_SP_REF: Final = re.compile(r"^azuread_service_principal\.([a-z0-9_]+)\.object_id$")
_GRAPH_ROLE: Final = re.compile(r'^local\.graph_roles\["([A-Za-z.]+)"\]$')
_SCOPE_REF: Final = re.compile(r"^(azurerm_[a-z_]+)\.([a-z0-9_]+)\.id$")


class TfParseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Block:
    file: str
    kind: str
    type: str
    name: str
    start: int
    """0-based index of the opening line."""
    end: int
    """0-based index of the closing ``}`` line."""
    attrs: dict[str, str] = field(default_factory=dict)
    attr_lines: dict[str, int] = field(default_factory=dict)

    @property
    def address(self) -> str:
        prefix = "data." if self.kind == "data" else ""
        return f"{prefix}{self.type}.{self.name}"


def _depth_delta(line: str) -> int:
    """Brace balance of one line, ignoring braces inside strings and comments."""
    depth = 0
    in_str = False
    i = 0
    while i < len(line):
        c = line[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "#" or line.startswith("//", i):
            break
        elif c in "{[(":
            depth += 1 if c == "{" else 0
        elif c in "}])":
            depth -= 1 if c == "}" else 0
        i += 1
    if in_str:
        raise TfParseError(f"unterminated string: {line.strip()[:60]}")
    return depth


def parse_blocks(path: Path) -> list[Block]:
    return parse_lines(path.name, path.read_text(encoding="utf-8").splitlines())


def parse_lines(name: str, lines: list[str]) -> list[Block]:
    """Top-level blocks of one file; ``name`` is the file name recorded on each block."""
    blocks: list[Block] = []
    i = 0
    while i < len(lines):
        m = _BLOCK_RE.match(lines[i])
        if not m:
            i += 1
            continue
        depth = 1
        attrs: dict[str, str] = {}
        attr_lines: dict[str, int] = {}
        j = i + 1
        while j < len(lines):
            if depth == 1 and (a := _ATTR_RE.match(lines[j])) and _depth_delta(lines[j]) == 0:
                attrs[a.group(1)] = a.group(2)
                attr_lines[a.group(1)] = j
            depth += _depth_delta(lines[j])
            if depth == 0:
                break
            j += 1
        if depth != 0:
            raise TfParseError(f"{name}: block {m.group(2)}.{m.group(3)} never closes")
        blocks.append(Block(name, m.group(1), m.group(2), m.group(3), i, j, attrs, attr_lines))
        i = j + 1
    return blocks


def load_lab(lab_dir: Path) -> dict[str, Block]:
    out: dict[str, Block] = {}
    for path in sorted(lab_dir.glob("*.tf")):
        for b in parse_blocks(path):
            out[b.address] = b
    return out


@dataclass(frozen=True, slots=True)
class Lever:
    """One Terraform change and the snapshot change it stands for."""

    address: str
    kind: LeverKind
    file: str
    description: str
    principal: str | None = None
    """Snapshot id of the principal whose grant this removes."""
    target: str | None = None
    """Snapshot id of the scope, Graph permission, owned app or storage account."""
    detail: str = ""
    """Role name, Graph permission value, or the attribute changed."""

    @property
    def key(self) -> str:
        return f"{self.address}#{self.kind}#{self.detail}"


@dataclass(frozen=True, slots=True)
class Unmapped:
    address: str
    reason: str


@dataclass(frozen=True, slots=True)
class LabMap:
    blocks: dict[str, Block]
    levers: tuple[Lever, ...]
    unmapped: tuple[Unmapped, ...]


def _literal(value: str) -> str | None:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return None


def _pattern(literal: str) -> re.Pattern[str]:
    """``"kv-crown-${local.suffix}"`` -> ``^kv-crown-[^/]+$`` (case-insensitive)."""
    parts = re.split(r"\$\{[^}]*\}", literal)
    return re.compile("^" + "[^/]+".join(re.escape(p) for p in parts) + "$", re.IGNORECASE)


def _one(matches: list[Entity], what: str) -> Entity:
    if len(matches) != 1:
        raise LookupError(f"{what}: {len(matches)} snapshot matches")
    return matches[0]


class _Resolver:
    def __init__(self, blocks: dict[str, Block], snapshot: Snapshot) -> None:
        self.blocks = blocks
        self.snapshot = snapshot

    def principal(self, expr: str) -> Entity:
        m = _SP_REF.match(expr)
        if not m:
            raise LookupError(f"principal {expr!r} is not a lab service principal")
        sp = self.blocks.get(f"azuread_service_principal.{m.group(1)}")
        if sp is None:
            raise LookupError(f"no block azuread_service_principal.{m.group(1)}")
        app_ref = re.match(
            r"^azuread_application\.([a-z0-9_]+)\.client_id$", sp.attrs.get("client_id", "")
        )
        app = self.blocks.get(f"azuread_application.{app_ref.group(1)}") if app_ref else None
        name = _literal(app.attrs.get("display_name", "")) if app else None
        if not name:
            raise LookupError(f"cannot find the display name of {sp.address}")
        return _one(
            [
                e
                for e in self.snapshot.entities
                if e.type == "servicePrincipal" and (e.display_name or "").lower() == name.lower()
            ],
            f"service principal {name}",
        )

    def application(self, block: Block) -> Entity:
        name = _literal(block.attrs.get("display_name", ""))
        if not name:
            raise LookupError(f"{block.address} has no literal display_name")
        return _one(
            [
                e
                for e in self.snapshot.entities
                if e.type == "application" and (e.display_name or "").lower() == name.lower()
            ],
            f"application {name}",
        )

    def scope(self, expr: str) -> Entity:
        literal = _literal(expr)
        if literal is not None:
            pat = _pattern(literal)
            return _one(
                [e for e in self.snapshot.entities if e.type == "scope" and pat.match(e.id)],
                f"scope {literal}",
            )
        m = _SCOPE_REF.match(expr)
        if not m:
            raise LookupError(f"scope {expr!r} is not understood")
        return self.named(f"{m.group(1)}.{m.group(2)}")

    def named(self, address: str) -> Entity:
        block = self.blocks.get(address)
        name = _literal(block.attrs.get("name", "")) if block else None
        if block is None or name is None:
            raise LookupError(f"{address} has no literal name")
        pat = _pattern(name)
        if block.type == "azurerm_resource_group":
            matches = [
                e
                for e in self.snapshot.entities
                if e.type == "scope"
                and "/resourcegroups/" in e.id
                and e.id.count("/") == 4
                and pat.match(e.id.rsplit("/", 1)[-1])
            ]
        else:
            matches = [
                e
                for e in self.snapshot.entities
                if e.type == "resource" and pat.match(e.id.rsplit("/", 1)[-1])
            ]
        return _one(matches, address)


def map_lab(lab_dir: Path, snapshot: Snapshot) -> LabMap:
    blocks = load_lab(lab_dir)
    r = _Resolver(blocks, snapshot)
    levers: list[Lever] = []
    unmapped: list[Unmapped] = []

    def skip(b: Block, reason: str) -> None:
        unmapped.append(Unmapped(b.address, reason))

    for b in sorted(blocks.values(), key=lambda b: b.address):
        if b.kind != "resource":
            continue
        try:
            if b.type == "azurerm_role_assignment":
                if "for_each" in b.attrs or "count" in b.attrs:
                    skip(b, "for_each/count blocks are not proposed")
                    continue
                role = _literal(b.attrs.get("role_definition_name", ""))
                principal_expr = b.attrs.get("principal_id", "")
                if principal_expr.startswith("data."):
                    skip(b, "grant to the operator running lab-up, not a workload")
                    continue
                if not role:
                    skip(b, "role_definition_name is not a literal")
                    continue
                p = r.principal(principal_expr)
                s = r.scope(b.attrs.get("scope", ""))
                levers.append(
                    Lever(
                        b.address,
                        "rbac",
                        b.file,
                        f"remove {role} for {p.display_name} on {s.id}",
                        p.id,
                        s.id,
                        role,
                    )
                )
            elif b.type == "azuread_app_role_assignment":
                if "for_each" in b.attrs or "count" in b.attrs:
                    skip(b, "for_each/count blocks are not proposed")
                    continue
                m = _GRAPH_ROLE.match(b.attrs.get("app_role_id", ""))
                if not m:
                    skip(b, "app_role_id is not a Graph permission lookup")
                    continue
                p = r.principal(b.attrs.get("principal_object_id", ""))
                levers.append(
                    Lever(
                        b.address,
                        "app-role",
                        b.file,
                        f"remove Graph {m.group(1)} from {p.display_name}",
                        p.id,
                        None,
                        m.group(1),
                    )
                )
            elif b.type == "azuread_application" and "owners" in b.attrs:
                refs = re.findall(
                    r"azuread_service_principal\.[a-z0-9_]+\.object_id", b.attrs["owners"]
                )
                if refs:
                    app = r.application(b)
                    for ref in refs:
                        p = r.principal(ref)
                        levers.append(
                            Lever(
                                b.address,
                                "owner",
                                b.file,
                                f"remove {p.display_name} as owner of {app.display_name}",
                                p.id,
                                app.id,
                                ref,
                            )
                        )
            elif (
                b.type == "azurerm_storage_account"
                and b.attrs.get("shared_access_key_enabled") == "true"
            ):
                s = r.named(b.address)
                levers.append(
                    Lever(
                        b.address,
                        "shared-key",
                        b.file,
                        f"disable shared-key access on {s.id.rsplit('/', 1)[-1]}",
                        None,
                        s.id,
                        "shared_access_key_enabled",
                    )
                )
        except LookupError as exc:
            skip(b, str(exc))
    return LabMap(blocks, tuple(sorted(levers, key=lambda x: x.key)), tuple(unmapped))


# -- snapshot side ---------------------------------------------------------------------


def apply_to_snapshot(snapshot: Snapshot, levers: tuple[Lever, ...]) -> Snapshot:
    """The snapshot as it would be after the Terraform change."""
    names = {e.id: (e.display_name or "") for e in snapshot.entities}
    drop: set[int] = set()
    no_shared_key: set[str] = set()
    for lever in levers:
        if lever.kind == "shared-key" and lever.target:
            no_shared_key.add(lever.target)
            continue
        for i, e in enumerate(snapshot.edges):
            if e.src != lever.principal:
                continue
            if (
                (
                    lever.kind == "rbac"
                    and isinstance(e, HasRbacRole)
                    and e.dst == lever.target
                    and names.get(e.role_definition_id, "").lower() == lever.detail.lower()
                )
                or (
                    lever.kind == "app-role"
                    and isinstance(e, HasAppRole)
                    and (e.app_role_value or "") == lever.detail
                )
                or (lever.kind == "owner" and isinstance(e, Owns) and e.dst == lever.target)
            ):
                drop.add(i)
    data = snapshot.model_dump(mode="json")
    data["edges"] = [e for i, e in enumerate(data["edges"]) if i not in drop]
    for ent in data["entities"]:
        if ent["id"] in no_shared_key:
            ent["properties"] = {**ent["properties"], "allowSharedKeyAccess": False}
    return Snapshot.model_validate(data)


def references_elsewhere(blocks: dict[str, Block], lab_dir: Path, address: str) -> list[str]:
    """Blocks (other than ``address`` itself) whose text mentions ``address``."""
    out = []
    for b in blocks.values():
        if b.address == address:
            continue
        lines = (lab_dir / b.file).read_text(encoding="utf-8").splitlines()[b.start : b.end + 1]
        if any(re.search(rf"\b{re.escape(address)}\b", line) for line in lines):
            out.append(b.address)
    return sorted(out)
