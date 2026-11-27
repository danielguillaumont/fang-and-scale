"""Size caps for every JSON and YAML file the tool reads (threat model, approved 2026-11-27).

A hostile or broken input file (a fixture's ``exchanges.json``, a snapshot, a plan,
a run directory sent in a pull request) must not exhaust memory. Every JSON or YAML
file is read through :func:`read_capped`, which refuses a file over its cap from
its size before reading it, and reads at most ``cap + 1`` bytes in case it grows
while being read. YAML keeps its own 1 MiB cap (``fns.yamlio``).

Standard library only, and importing nothing from ``fns``: the verifier uses it too,
and must stay apart from the prover and the executor.
"""

from __future__ import annotations

from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Final

MiB: Final = 1024 * 1024

MAX_JSON_BYTES: Final = 64 * MiB
"""Snapshots and fixture exchanges: the largest inputs. A real tenant's snapshot is
a few MiB; 64 MiB leaves room and still bounds memory."""
MAX_RECORD_BYTES: Final = 16 * MiB
"""Everything the tool writes itself and reads back: plans, run records, reports,
assertions, bundles, probe artifacts, results, signatures."""


class InputTooLargeError(ValueError):
    """A file over its size cap. Nothing of it was parsed."""


def read_capped(source: Path | Traversable, cap: int, what: str | None = None) -> bytes:
    """The file's bytes, or :class:`InputTooLargeError` if it is over ``cap``."""
    name = what or getattr(source, "name", "input")
    if isinstance(source, Path) and source.stat().st_size > cap:
        raise InputTooLargeError(f"{name} is larger than {cap} bytes")
    with source.open("rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise InputTooLargeError(f"{name} is larger than {cap} bytes")
    return data


def read_capped_text(source: Path | Traversable, cap: int, what: str | None = None) -> str:
    """:func:`read_capped`, decoded as UTF-8."""
    return read_capped(source, cap, what).decode("utf-8")
