"""Process exit codes. CI gates on these, so they are defined in one place.

The README's exit code table is the contract (``tests/test_exit_codes.py``):

- 0: within budget, or the check passed;
- 1: the contract failed. Commands that run another kind of check exit 1 when
  that check fails: ``mutate`` (survivors over the limit), ``harden`` (no
  proposal satisfies the contract), ``record`` (a recorded operation conflicts
  with ``must_not_reach``), ``detections check`` and ``schema --check``;
- 2: usage or invalid input: bad arguments, a missing or invalid contract,
  scope, snapshot, report or log file, inputs from different runs, or an
  internal error. Click/Typer also exits 2 on bad arguments;
- 3: inconclusive findings over the contract's budget;
- 4: the scope gate refused the run (tenant pinning);
- 5: the verifier refused a run directory (tampered or incomplete evidence).

A crash must never look like a verdict, so ``fns.cli.main`` turns an unexpected
exception into 2.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    CONTRACT_FAILED = 1
    CHECK_FAILED = 1
    USAGE = 2
    INVALID_INPUT = 2
    NOT_IMPLEMENTED = 2
    INTERNAL_ERROR = 2
    INCONCLUSIVE_OVER_BUDGET = 3
    SCOPE_DENIED = 4
    EVIDENCE_INVALID = 5
    """The verifier refused a run directory (tampered or incomplete input)."""
