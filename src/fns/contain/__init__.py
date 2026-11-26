"""Antivenom: assumed-compromise reach over a snapshot (M2, ``fns contain``).

Pure functions over a :class:`fns.models.snapshot.Snapshot`: no I/O, no API
calls, nothing from ``fns.adapters``. M2 produces rung 1 (modeled) evidence
only, so a finding can fail here but never pass (docs/milestones/M2.md).
"""
