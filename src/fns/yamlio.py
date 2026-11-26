"""Strict YAML loading for user-authored files (scope.yaml, contracts).

Compared with ``yaml.safe_load``:

- duplicate mapping keys are an error (PyYAML silently keeps the last one, so
  ``tenant_id`` written twice would pin the wrong tenant without warning);
- aliases/anchors are rejected (no alias-expansion bombs; config never needs them);
- timestamps stay strings so Pydantic does the timezone validation;
- only ``true``/``false`` are booleans (YAML 1.1 treats ``no``/``on``/``off`` as bools);
- the document must be a single mapping, and files over 1 MiB are refused.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node

MAX_BYTES = 1024 * 1024


class YamlError(ValueError):
    """A YAML document that is malformed or uses a forbidden feature."""


class _StrictLoader(yaml.SafeLoader):
    pass


# Rebuild implicit resolvers without timestamps and with YAML 1.2-style booleans.
_StrictLoader.yaml_implicit_resolvers = {
    first: [
        (tag, rx)
        for tag, rx in resolvers
        if tag not in {"tag:yaml.org,2002:timestamp", "tag:yaml.org,2002:bool"}
    ]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"), list("tf")
)


def _compose_node(self: _StrictLoader, parent: Node | None, index: object) -> Node | None:
    event = self.peek_event()  # type: ignore[no-untyped-call]
    line = event.start_mark.line + 1
    if isinstance(event, yaml.AliasEvent):
        raise YamlError(f"YAML aliases are not allowed (line {line})")
    if getattr(event, "anchor", None) is not None:
        raise YamlError(f"YAML anchors are not allowed (line {line})")
    return yaml.SafeLoader.compose_node(self, parent, index)  # type: ignore[arg-type]


def _construct_mapping(
    self: _StrictLoader, node: MappingNode, deep: bool = False
) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = self.construct_object(key_node, deep=deep)
        if key in seen:
            raise YamlError(f"duplicate key {key!r} (line {key_node.start_mark.line + 1})")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(self, node, deep=deep)


_StrictLoader.compose_node = _compose_node  # type: ignore[method-assign,assignment]
_StrictLoader.construct_mapping = _construct_mapping  # type: ignore[method-assign,assignment]


def loads_yaml(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise YamlError("YAML document exceeds 1 MiB")
    try:
        docs = list(yaml.load_all(text, Loader=_StrictLoader))
    except yaml.YAMLError as exc:
        raise YamlError(str(exc)) from exc
    if len(docs) != 1:
        raise YamlError("expected exactly one YAML document")
    doc = docs[0]
    if not isinstance(doc, dict):
        raise YamlError("top level of the YAML document must be a mapping")
    return doc


def load_yaml(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_BYTES:
        raise YamlError(f"{path} exceeds 1 MiB")
    return loads_yaml(path.read_text(encoding="utf-8"))


def dumps_yaml(data: dict[str, Any]) -> str:
    """Deterministic YAML for files the tool writes (keys in insertion order)."""
    text: str = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
    return text
