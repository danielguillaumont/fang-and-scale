"""JSON Schema export for user-facing file formats.

Output is deterministic (sorted keys, 2-space indent, LF, trailing newline) so
the committed files in ``schemas/`` can be checked for drift in CI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel

from fns.models.assertions import AssertionSet
from fns.models.bundle import EvidenceBundle
from fns.models.contract import Contract
from fns.models.mutation import MutationReport
from fns.models.report import ContainReport
from fns.models.scope import ScopeManifest
from fns.models.snapshot import Snapshot

DRAFT: Final = "https://json-schema.org/draft/2020-12/schema"
SCHEMAS: Final[dict[str, type[BaseModel]]] = {
    "assertions": AssertionSet,
    "contain-report": ContainReport,
    "evidence-bundle": EvidenceBundle,
    "mutation-report": MutationReport,
    "contract": Contract,
    "scope": ScopeManifest,
    "snapshot": Snapshot,
}


def schema_for(name: str) -> dict[str, Any]:
    model = SCHEMAS[name]
    schema = model.model_json_schema(mode="validation")
    return {"$schema": DRAFT, **schema}


def render(name: str) -> str:
    return json.dumps(schema_for(name), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def filename(name: str) -> str:
    return f"{name}.schema.json"


def write_all(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name in sorted(SCHEMAS):
        path = out_dir / filename(name)
        path.write_text(render(name), encoding="utf-8", newline="\n")
        written.append(path)
    return written


def drifted(out_dir: Path) -> list[Path]:
    """Schemas whose committed bytes differ from what the models generate."""
    stale = []
    for name in sorted(SCHEMAS):
        path = out_dir / filename(name)
        if not path.is_file() or path.read_bytes() != render(name).encode("utf-8"):
            stale.append(path)
    return stale
