"""Verifier (fns prove, M3).

Trust boundary: this package must never import proposer (fns.harden), executor
(fns.strike) or adapter (fns.adapters) code. Enforced by import-linter in
``uv run poe check``.
"""
