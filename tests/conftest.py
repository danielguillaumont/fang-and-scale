"""Shared test configuration.

Hypothesis profiles: ``dev`` (default) for fast local runs, ``ci`` for deeper
search. Select with ``HYPOTHESIS_PROFILE=ci``. Deadlines are off because
Windows runners have noisy timing.
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, settings

settings.register_profile("dev", max_examples=100, deadline=None)
settings.register_profile(
    "ci",
    max_examples=1000,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))
