"""Scope operations: the API calls the tool itself is allowed to make.

Grammar (exact match only; no wildcards in M1):

    arm:<Namespace>/<type>[/<type>...]/<read|write|delete|action>
        e.g. arm:Microsoft.Authorization/roleAssignments/read
    graph:<METHOD> <path template>[/$ref]
        e.g. graph:GET /servicePrincipals/{id}/owners
    kv:GET /secrets | kv:GET /secrets/<name>
        Key Vault data plane (M3 P5.1): list secret names, or get one secret
    blob:HEAD /<container>/<blob>
        Blob data plane (M3 P5.1): blob properties only, never content

Classification: ARM ``read`` is a read; ``write``, ``delete`` and ``action``
are not (``listKeys/action`` returns secrets). Graph ``GET`` is a read; any
other method is not, unless it is on :data:`SAFE_POST_READS` (empty in M1).
The data-plane forms are reads by construction: the grammar has no other method
for them, so ``kv:PUT ...`` or ``blob:GET ...`` is not an operation at all. Their
names are literal (no templates), so a scope names exactly which objects may be
read; the gate also binds each one to its resource (``ScopeManifest.data_objects``).

These are distinct from *contract* operations, which describe what a
compromised identity could do (see ``fns.models.contract``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

Api = Literal["arm", "graph", "kv", "blob"]
DATA_PLANE_APIS: Final[frozenset[str]] = frozenset({"kv", "blob"})

_ARM_RE = re.compile(
    r"^arm:(?P<ns>[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+)"
    r"(?P<types>(?:/[A-Za-z][A-Za-z0-9]*)+)/(?P<verb>read|write|delete|action)$",
    re.IGNORECASE,
)
_GRAPH_RE = re.compile(
    r"^graph:(?P<method>GET|POST|PUT|PATCH|DELETE) "
    r"(?P<path>(?:/(?:\{id\}|[A-Za-z][A-Za-z0-9.]*))+(?:/\$ref)?)$"
)
# Key Vault secret names: 1-127 of [0-9A-Za-z-] (Key Vault rules).
_KV_RE = re.compile(r"^kv:GET (?P<path>/secrets(?:/[0-9A-Za-z-]{1,127})?)$")
# Container: 3-63 lowercase letters, digits and single hyphens, starting and ending
# with a letter or digit (Azure rules). Blob: flat names only, no "/", not "." or "..".
_BLOB_RE = re.compile(
    r"^blob:HEAD /(?P<container>[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){2,62})"
    r"/(?P<blob>(?!\.{1,2}$)[A-Za-z0-9._-]{1,256})$"
)

# Graph POSTs that only read. Empty in M1; additions need a DECISIONS row.
SAFE_POST_READS: Final[frozenset[str]] = frozenset()


# The only write operations that exist (M4, docs/milestones/M4-strikes-plan.md). A scope
# may list a write under ``strike`` only if it is one of these; ``fns.scope.writes``
# holds the rule for each (method, path, body). Additions need a DECISIONS row.
WRITE_FORM_OPERATIONS: Final[tuple[str, ...]] = (
    "arm:Microsoft.Storage/storageAccounts/listKeys/action",
    "arm:Microsoft.Storage/storageAccounts/regenerateKey/action",
    "arm:Microsoft.KeyVault/vaults/write",
    "graph:POST /applications/{id}/addPassword",
    "graph:POST /applications/{id}/removePassword",
    "graph:PATCH /applications/{id}",
    "graph:POST /servicePrincipals/{id}/appRoleAssignedTo",
    "graph:DELETE /servicePrincipals/{id}/appRoleAssignedTo/{id}",
    "graph:POST /applications/{id}/owners/$ref",
    "graph:DELETE /applications/{id}/owners/{id}/$ref",
)


class OperationError(ValueError):
    """Raised for an operation string outside the grammar."""


@dataclass(frozen=True, slots=True)
class Operation:
    api: Api
    raw: str
    key: str  # canonical comparison key (ARM and Graph paths are case-insensitive)
    is_read: bool
    path: str = ""
    """Data-plane request path (``/secrets/<name>``, ``/<container>/<blob>``); empty
    for ARM and Graph. Secret names are case-insensitive, blob names are not."""

    @property
    def is_data_plane(self) -> bool:
        return self.api in DATA_PLANE_APIS


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
    if m := _KV_RE.fullmatch(value):
        path = m["path"].lower()
        return Operation("kv", value, f"kv:GET {path}", True, path)
    if m := _BLOB_RE.fullmatch(value):
        path = f"/{m['container']}/{m['blob']}"
        return Operation("blob", value, f"blob:HEAD {path}", True, path)
    raise OperationError(
        f"invalid operation {value!r}: expected "
        "'arm:<Namespace>/<type>/<read|write|delete|action>', 'graph:<METHOD> /<path>', "
        "'kv:GET /secrets[/<name>]' or 'blob:HEAD /<container>/<blob>'"
    )


WRITE_FORM_KEYS: Final[frozenset[str]] = frozenset(
    parse_operation(op).key for op in WRITE_FORM_OPERATIONS
)
