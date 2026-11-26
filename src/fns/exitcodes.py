"""Process exit codes. CI gates on these, so they are defined in one place.

Note: Click/Typer also exits 2 on usage errors, so ``NOT_IMPLEMENTED`` currently
shares a code with bad arguments (M1 spec). Change it here if that becomes a
problem for CI consumers.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    CONTRACT_FAILED = 1
    INVALID_INPUT = 1
    USAGE = 2
    NOT_IMPLEMENTED = 2
    INCONCLUSIVE_OVER_BUDGET = 3
    SCOPE_DENIED = 4
