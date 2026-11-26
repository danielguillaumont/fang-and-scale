"""The smallest Terraform change after which the contract holds in the model.

Exact search over subsets of mapped levers, smallest first (docs/milestones/M4.md,
K1). A subset satisfies the contract when, on the mutated snapshot:

- no ``must_not_reach`` finding is ``fail``, and
- every ``must_still_do`` item the model allowed before is still allowed.

Read-only: produces a diff and a plan hash; applying it is not available.
"""

from __future__ import annotations

import difflib
import hashlib
import itertools
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from fns.contain.closure import Closure, SnapshotIndex
from fns.contain.evaluate import Evaluation, evaluate
from fns.harden.tfmap import LabMap, Lever, apply_to_snapshot, map_lab, references_elsewhere
from fns.models.contract import Contract
from fns.models.evidence import Finding
from fns.models.snapshot import Snapshot

MAX_LEVERS: Final = 4
MAX_CANDIDATES: Final = 16


@dataclass(frozen=True, slots=True)
class State:
    critical: int
    still_do_allowed: tuple[str, ...]
    """Finding ids of must_still_do items the model allows."""
    failing: tuple[str, ...]
    """``target operation`` of failing must_not_reach items."""


@dataclass(frozen=True, slots=True)
class Proposal:
    levers: tuple[Lever, ...]
    before: State
    after: State
    diff: str
    plan_hash: str
    candidates: tuple[Lever, ...]
    """Levers considered (those touching identities the compromised principal controls,
    or the contract's resources)."""
    rejected: tuple[tuple[str, str], ...]
    """(address, reason) for levers that could not be proposed."""
    evaluated: int
    """How many candidate subsets were evaluated."""
    alternatives: tuple[tuple[Lever, ...], ...] = ()
    """Other lever sets of the same (minimal) size that also satisfy the contract."""


class NoProposalError(RuntimeError):
    pass


def _allowed(f: Finding) -> bool:
    return any(e.rung == "modeled" and e.outcome == "allowed" for e in f.evidence)


def state(ev: Evaluation) -> State:
    fs = [o.finding for o in ev.outcomes]
    return State(
        critical=ev.summary.critical,
        still_do_allowed=tuple(
            sorted(f.id for f in fs if f.item_kind == "must_still_do" and _allowed(f))
        ),
        failing=tuple(
            sorted(
                f"{f.target} {f.operation}"
                for f in fs
                if f.item_kind == "must_not_reach" and f.verdict == "fail"
            )
        ),
    )


def _relevant(lever: Lever, controlled: frozenset[str], targets: frozenset[str]) -> bool:
    if lever.kind == "shared-key":
        return lever.target in targets
    return lever.principal in controlled


def minimize(
    contract: Contract, snapshot: Snapshot, lab_dir: Path, *, lab: LabMap | None = None
) -> Proposal:
    lab = lab or map_lab(lab_dir, snapshot)
    base = evaluate(contract, snapshot)
    before = state(base)
    if base.compromised is None:
        raise NoProposalError("the compromised identity does not resolve in the snapshot")
    closure = Closure(SnapshotIndex(snapshot), base.compromised)
    controlled = frozenset(closure.controlled())
    targets = frozenset(o.finding.target for o in base.outcomes)  # resolved below to ids via names
    target_ids = frozenset(
        e.id
        for e in snapshot.entities
        if e.type == "resource"
        and any(t.endswith(":" + e.id.rsplit("/", 1)[-1]) or t.endswith(e.id) for t in targets)
    )
    rejected = [(u.address, u.reason) for u in lab.unmapped]
    candidates: list[Lever] = []
    for lever in lab.levers:
        refs = references_elsewhere(lab.blocks, lab_dir, lever.address)
        if lever.kind in {"rbac", "app-role"} and refs:
            rejected.append((lever.address, f"referenced by {', '.join(refs)}"))
            continue
        if _relevant(lever, controlled, target_ids):
            candidates.append(lever)
    if len(candidates) > MAX_CANDIDATES:
        raise NoProposalError(f"{len(candidates)} candidate levers; the exact search stops at 16")

    def ok(s: State) -> bool:
        return s.critical == 0 and set(before.still_do_allowed) <= set(s.still_do_allowed)

    evaluated = 0
    found: list[tuple[tuple[Lever, ...], State]] = []
    if ok(before):
        found.append(((), before))
    else:
        for size in range(1, min(MAX_LEVERS, len(candidates)) + 1):
            for combo in itertools.combinations(candidates, size):
                evaluated += 1
                s = state(evaluate(contract, apply_to_snapshot(snapshot, combo)))
                if ok(s):
                    found.append((combo, s))
            if found:
                break
    chosen, after = found[0] if found else (None, before)
    if chosen is None:
        raise NoProposalError(
            f"no combination of up to {MAX_LEVERS} levers satisfies the contract "
            f"({evaluated} evaluated)"
        )
    diff = render_diff(lab_dir, lab, chosen)
    return Proposal(
        levers=chosen,
        before=before,
        after=after,
        diff=diff,
        plan_hash=hashlib.sha256(diff.encode("utf-8")).hexdigest(),
        candidates=tuple(candidates),
        rejected=tuple(sorted(rejected)),
        evaluated=evaluated,
        alternatives=tuple(c for c, _ in found[1:]),
    )


# -- Terraform side -----------------------------------------------------------------------


def _edit_lines(lines: list[str | None], lab: LabMap, lever: Lever) -> None:
    """Edit in place; deleted lines become None so later edits keep their indices."""
    block = lab.blocks[lever.address]
    if lever.kind in {"rbac", "app-role"}:
        end = block.end
        # Also drop the blank line after the block so spacing stays even.
        if end + 1 < len(lines) and not (lines[end + 1] or "x").strip():
            end += 1
        for k in range(block.start, end + 1):
            lines[k] = None
        return
    i = block.attr_lines[lever.detail if lever.kind == "shared-key" else "owners"]
    line = lines[i]
    if line is None:
        raise NoProposalError(f"{lever.address} was already removed")
    if lever.kind == "shared-key":
        lines[i] = line.replace("= true", "= false", 1)
        return
    ref = lever.detail
    new = line.replace(f", [{ref}]", "").replace(f"[{ref}]", "[]").replace(f", {ref}", "")
    new = new.replace("concat(local.owners)", "local.owners")
    if new == line:
        raise NoProposalError(f"cannot remove {ref} from {lever.address}.owners")
    lines[i] = new


def edited_files(
    lab_dir: Path, lab: LabMap, levers: tuple[Lever, ...]
) -> dict[str, tuple[list[str], list[str]]]:
    """File name -> (old lines, new lines) after applying the levers."""
    by_file: dict[str, list[Lever]] = {}
    for lever in levers:
        by_file.setdefault(lever.file, []).append(lever)
    out: dict[str, tuple[list[str], list[str]]] = {}
    for name in sorted(by_file):
        old = (lab_dir / name).read_text(encoding="utf-8").splitlines(keepends=False)
        work: list[str | None] = list(old)
        for lever in by_file[name]:
            _edit_lines(work, lab, lever)
        out[name] = (old, [line for line in work if line is not None])
    return out


def render_diff(lab_dir: Path, lab: LabMap, levers: tuple[Lever, ...]) -> str:
    chunks: list[str] = []
    for name, (old, new) in edited_files(lab_dir, lab, levers).items():
        chunks.extend(
            difflib.unified_diff(
                [f"{line}\n" for line in old],
                [f"{line}\n" for line in new],
                fromfile=f"a/lab/{name}",
                tofile=f"b/lab/{name}",
            )
        )
    return "".join(chunks)
