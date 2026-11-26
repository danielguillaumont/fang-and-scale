"""Base model, canonical JSON and digests.

Canonical JSON: UTF-8, keys sorted, no insignificant whitespace, no floats.
For the value types these models allow, that is byte-identical to RFC 8785
(JCS) except for key ordering of non-BMP characters, which our keys never use.

Volatile fields (timestamps, request IDs, collector version, timings) are
declared per class in ``__volatile__`` and dropped when computing a digest, so
two collections of the same tenant state produce the same digest.
"""

from __future__ import annotations

import enum
import hashlib
import json
import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from fns.models.ids import utc_isoformat


class CanonicalError(TypeError):
    """A value that has no canonical JSON form (floats, unknown types)."""


class FnsModel(BaseModel):
    """Immutable, closed-world base for every persisted model."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        use_attribute_docstrings=True,
        str_strip_whitespace=False,
    )

    __volatile__: ClassVar[frozenset[str]] = frozenset()
    __omit_empty__: ClassVar[frozenset[str]] = frozenset()
    """Fields added after data was recorded: left out of the canonical form while
    empty, so digests of earlier snapshots and reports do not change."""

    def canonical_json(self, *, for_digest: bool = False) -> str:
        return canonical_dumps(to_canonical(self, for_digest=for_digest))

    def digest(self) -> str:
        """sha256 (hex) of the canonical JSON with volatile fields removed."""
        return sha256_hex(self.canonical_json(for_digest=True))


def to_canonical(value: Any, *, for_digest: bool = False) -> Any:
    """Convert a model tree into plain JSON values, optionally dropping volatile fields."""
    if isinstance(value, BaseModel):
        cls = type(value)
        volatile: frozenset[str] = (
            getattr(cls, "__volatile__", frozenset()) if for_digest else frozenset()
        )
        omit: frozenset[str] = getattr(cls, "__omit_empty__", frozenset())
        return {
            name: to_canonical(getattr(value, name), for_digest=for_digest)
            for name in cls.model_fields
            if name not in volatile and not (name in omit and getattr(value, name) in ((), None))
        }
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalError("floats are not allowed in canonical models")
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return utc_isoformat(value)
    if isinstance(value, enum.Enum):
        return to_canonical(value.value, for_digest=for_digest)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalError(f"mapping keys must be strings, got {type(k).__name__}")
            out[k] = to_canonical(v, for_digest=for_digest)
        return out
    if isinstance(value, (list, tuple)):
        return [to_canonical(v, for_digest=for_digest) for v in value]
    raise CanonicalError(f"no canonical form for {type(value).__name__}")


def canonical_dumps(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
