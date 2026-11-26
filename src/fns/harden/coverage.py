"""Which parts of the reach model have a detection rule (M4 K3, H5)."""

from __future__ import annotations

from fns.contain import semantics as sem
from fns.contain.closure import RULES
from fns.harden.detections import DetectionRule


def rule_name(fn: object) -> str:
    """``_rule_owner_adds_credential`` -> ``owner-adds-credential``."""
    return getattr(fn, "__name__", "").removeprefix("_rule_").replace("_", "-")


def coverage_keys() -> list[str]:
    keys = [f"rule:{rule_name(r)}" for r in RULES]
    keys += [f"op:{s.target}:{s.operation}" for s in sem.TABLE.values()]
    keys += [f"way:{w}" for w in sorted(sem.INDIRECT_WAYS)]
    return sorted(set(keys))


def coverage_gaps(rules: list[DetectionRule], exempt: dict[str, str]) -> list[str]:
    keys = set(coverage_keys())
    covered = {c for r in rules for c in r.covers}
    problems = [
        f"no detection covers {k} (add a rule or an EXEMPT.yaml reason)"
        for k in sorted(keys - covered - set(exempt))
    ]
    problems += [f"covers unknown key {c}" for c in sorted(covered - keys)]
    problems += [f"EXEMPT.yaml lists unknown key {k}" for k in sorted(set(exempt) - keys)]
    problems += [
        f"EXEMPT.yaml exempts {k}, which a rule covers" for k in sorted(set(exempt) & covered)
    ]
    return problems
