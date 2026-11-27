"""Shared test configuration.

Hypothesis profiles: ``dev`` (default) for fast local runs, ``ci`` for deeper
search. Select with ``HYPOTHESIS_PROFILE=ci``. Deadlines are off because
Windows runners have noisy timing.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from hypothesis import HealthCheck, settings

from fns.journal import sqlite as journal_sqlite

settings.register_profile("dev", max_examples=100, deadline=None)
settings.register_profile(
    "ci",
    max_examples=1000,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))


@pytest.fixture(scope="session", autouse=True)
def _journals_without_fsync() -> Iterator[None]:
    """In-process test journals skip fsync (``PRAGMA synchronous = OFF``).

    The product always uses FULL (``tests/journal/test_durability.py``). No test can
    observe an fsync, and on Windows the commits were most of the suite's time.
    Set ``FNS_TEST_JOURNAL_FSYNC=1`` to run the suite with FULL.
    """
    if os.environ.get("FNS_TEST_JOURNAL_FSYNC") == "1":
        yield
        return
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(journal_sqlite, "SYNCHRONOUS", "OFF")
        yield
