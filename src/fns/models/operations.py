"""Scope operations: the API calls the tool itself is allowed to make.

Grammar (exact match only; no wildcards in M1):

    arm:<Namespace>/<type>[/<type>...]/<read|write|delete|action>
        e.g. arm:Microsoft.Authorization/roleAssignments/read
    graph:<METHOD> <path template>
        e.g. graph:GET /servicePrincipals/{id}/owners

Classification: ARM ``read`` is a read; ``write``, ``delete`` and ``action``
are not (``listKeys/action`` returns secrets). Graph ``GET`` is a read; any
other method is not, unless it is on :data:`SAFE_POST_READS` (empty in M1).

These are distinct from *contract* operations, which describe what a
compromised identity could do (see ``fns.models.contract``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

Api = Literal["arm", "graph"]

_ARM_RE = re.compile(
    r"^arm:(?P<ns>[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+)"
    r"(?P<types>(?:/[A-Za-z][A-Za-z0-9]*)+)/(?P<verb>read|write|delete|action)$",
    re.IGNORECASE,
)
_GRAPH_RE = re.compile(
    r"^graph:(?P<method>GET|POST|PUT|PATCH|DELETE) "
    r"(?P<path>(?:/(?:\{id\}|[A-Za-z][A-Za-z0-9.]*))+)$"
)

# Graph POSTs that only read. Empty in M1; additions need a DECISIONS row.
SAFE_POST_READS: Final[frozenset[str]] = frozenset()


class OperationError(ValueError):
    """Raised for an operation string outside the grammar."""


@dataclass(frozen=True, slots=True)
class Operation:
    api: Api
    raw: str
    key: str  # canonical comparison key (ARM and Graph paths are case-insensitive)
    is_read: bool


def parse_operation(value: object) -> Operation:
    if not isinstance(value, str):
        raise OperationError("operation must be a string")
    if m := _ARM_RE.fullmatch(value):
        verb = m["verb"].lower()
        return Operation("arm", value, value.lower(), verb == "read")
    if m := _GRAPH_RE.fullmatch(value):
        method = m["method"]
        key = f"graph:{method} {m['path'].lower()}"
        is_read = method == "GET" or key in SAFE_POST_READS
        return Operation("graph", value, key, is_read)
    raise OperationError(
        f"invalid operation {value!r}: expected "
        "'arm:<Namespace>/<type>/<read|write|delete|action>' or 'graph:<METHOD> /<path>'"
    )
