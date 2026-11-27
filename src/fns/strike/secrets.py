"""Secrets in strike responses (M4 strike plan, "Secrets in responses").

Three responses carry secrets: ``listKeys`` (``keys``), ``addPassword``
(``secretText``) and the token endpoint (``access_token``). :func:`strip_secrets`
removes every secret-bearing field from a response body **before** the response
object exists for any other code (the transport calls it on the raw JSON). What it
removes goes into a :class:`SecretHolder`, in memory only:

- nothing ever reads the storage keys; they are kept only so the holder can say
  how many it dropped, then wiped;
- S4 alone reads the password it needs (to ask for the token) and the token (to
  read its ``oid`` and ``roles`` claims, and to send its two requests through
  :class:`HeldToken`). The holder is wiped when the run ends. The token is never
  written anywhere: the journal gets its ``oid`` and ``roles`` claims only.

The holder never prints its values: ``repr`` and ``str`` show names and counts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from fns.adapters.azure.http import TransportError
from fns.models.operations import Api

SECRET_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "keys",  # Storage listKeys / regenerateKey: [{keyName, value, permissions}]
        "secretText",  # Graph addPassword
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "clientSecret",
        "password",
        "primaryKey",
        "secondaryKey",
        "connectionString",
    }
)
"""Field names removed wherever they appear in a response body, at any depth."""

REMOVED: Final = "REDACTED"
"""The same marker as recorded fixtures (``fns.fixtures.sanitize.REDACTED``)."""


def strip_secrets(body: object, path: str = "") -> tuple[Any, dict[str, Any]]:
    """Return ``(clean body, {json path: removed value})``. Never mutates ``body``."""
    found: dict[str, Any] = {}
    if isinstance(body, Mapping):
        clean: dict[str, Any] = {}
        for k, v in body.items():
            here = f"{path}/{k}"
            if str(k) in SECRET_FIELDS:
                found[here] = v
                clean[str(k)] = REMOVED
                continue
            inner, more = strip_secrets(v, here)
            clean[str(k)] = inner
            found.update(more)
        return clean, found
    if isinstance(body, list):
        items = []
        for i, v in enumerate(body):
            inner, more = strip_secrets(v, f"{path}/{i}")
            items.append(inner)
            found.update(more)
        return items, found
    return body, found


def secret_values(found: Mapping[str, Any]) -> list[str]:
    """Every string inside the removed values (for tests and the leak check)."""
    out: list[str] = []

    def walk(v: object) -> None:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, Mapping):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    for v in found.values():
        walk(v)
    return out


@dataclass
class SecretHolder:
    """Removed secrets, by the step that received them. In memory only."""

    _held: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)

    def put(self, step: str, found: Mapping[str, Any]) -> None:
        if found:
            self._held.setdefault(step, {}).update(found)

    def get(self, step: str, json_path: str) -> Any:
        """The one read path: S4 asks for S3's ``/secretText``."""
        return self._held.get(step, {}).get(json_path)

    def drop(self, step: str) -> None:
        """Forget one step's secrets now (S3's password once S4 holds its token, or a
        token whose claims prove nothing)."""
        held = self._held.pop(step, None)
        if held is not None:
            held.clear()

    def count_for(self, step: str) -> int:
        return len(self._held.get(step, {}))

    def count(self) -> int:
        return sum(len(v) for v in self._held.values())

    def wipe(self) -> None:
        for v in self._held.values():
            v.clear()
        self._held.clear()

    def __repr__(self) -> str:
        names = {k: sorted(v) for k, v in self._held.items()}
        return f"SecretHolder({names})"

    __str__ = __repr__


ACCESS_TOKEN: Final = "/access_token"  # noqa: S105 - a JSON path, not a secret


@dataclass(frozen=True)
class HeldToken:
    """The escalated identity's token provider (S4): Graph only, read from the holder
    on every call, so a wipe or :meth:`SecretHolder.drop` ends it at once."""

    holder: SecretHolder = field(repr=False)
    step: str

    def token(self, api: Api) -> str:
        if api != "graph":
            raise TransportError(f"the escalated identity has no {api} token")
        value = self.holder.get(self.step, ACCESS_TOKEN)
        if not isinstance(value, str) or not value:
            raise TransportError("the escalated token is gone")
        return value
