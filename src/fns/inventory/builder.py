"""Order-independent snapshot assembly.

Collectors add entities and edges in whatever order the APIs return them.
The builder resolves duplicates deterministically, so page order or request
order never changes the snapshot:

- entities: the candidate with the lowest priority wins (real records beat
  stubs inferred from a principal type); ties break on canonical JSON;
- edges: identical identity keys collapse to the canonically smallest;
- edges whose endpoints were never collected are dropped and reported in
  coverage instead of failing the snapshot.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from pydantic import TypeAdapter

from fns.models.snapshot import (
    Edge,
    Entity,
    EntityType,
    NotCollected,
    Provenance,
    Snapshot,
    SnapshotCoverage,
)

PRIORITY_PRIMARY: Final = 10  # the listing that owns this entity type
PRIORITY_REFERENCE: Final = 50  # seen as an owner/member with @odata.type
PRIORITY_STUB: Final = 100  # inferred (ARM principalType, deny-assignment principal)

_EDGE: Final[TypeAdapter[Edge]] = TypeAdapter(Edge)


class SnapshotBuilder:
    def __init__(self) -> None:
        self._entities: dict[str, tuple[int, str, Entity]] = {}
        self._edges: dict[tuple[str, ...], tuple[str, Edge]] = {}

    def entity(
        self,
        id_: str,
        type_: EntityType,
        *,
        display_name: str | None = None,
        properties: dict[str, Any] | None = None,
        priority: int = PRIORITY_PRIMARY,
    ) -> str:
        """Register a candidate entity; returns its normalized id."""
        ent = Entity.model_validate(
            {"id": id_, "type": type_, "display_name": display_name, "properties": properties or {}}
        )
        cand = (priority, ent.canonical_json(), ent)
        cur = self._entities.get(ent.id)
        if cur is None or cand[:2] < cur[:2]:
            self._entities[ent.id] = cand
        return ent.id

    def has(self, id_: str) -> bool:
        return id_.lower() in self._entities

    def edge(self, data: dict[str, Any], provenance: Provenance) -> None:
        edge = _EDGE.validate_python({**data, "provenance": provenance})
        key = edge.sort_key()
        text = edge.canonical_json(for_digest=True)
        cur = self._edges.get(key)
        if cur is None or text < cur[0]:
            self._edges[key] = (text, edge)

    def build(
        self,
        *,
        mode: str,
        tenant_id: str,
        collected_at: datetime,
        collector_version: str,
        coverage: SnapshotCoverage,
    ) -> Snapshot:
        known = set(self._entities)
        edges = []
        dropped = 0
        for _, edge in self._edges.values():
            if edge.src in known and edge.dst in known:
                edges.append(edge)
            else:
                dropped += 1
        not_collected = list(coverage.not_collected)
        if dropped:
            not_collected.append(
                NotCollected(
                    surface="edges",
                    reason=f"{dropped} edge(s) dropped: an endpoint was not collected",
                )
            )
        return Snapshot.model_validate(
            {
                "version": 1,
                "mode": mode,
                "tenant_id": tenant_id,
                "collected_at": collected_at,
                "collector_version": collector_version,
                "entities": [e for _, _, e in self._entities.values()],
                "edges": edges,
                "coverage": SnapshotCoverage(
                    collectors=coverage.collectors, not_collected=tuple(not_collected)
                ),
            }
        )
