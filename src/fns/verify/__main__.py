"""Entry point of the verifier process: ``python -m fns.verify run|check --run DIR``.

Uses argparse rather than the main CLI so this process loads nothing outside
``fns.verify`` and ``fns.models`` (import-linter enforces the boundary).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fns.verify.main import check, run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fns.verify")
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="judge a run directory and write the signed bundle")
    r.add_argument("--run", type=Path, required=True)
    r.add_argument("--sign", choices=["offline-test", "sigstore", "none"], default="offline-test")
    r.add_argument("--identity", default="unspecified")
    c = sub.add_parser("check", help="re-verify a finished run directory")
    c.add_argument("--run", type=Path, required=True)
    c.add_argument("--sigstore-identity")
    c.add_argument("--sigstore-issuer")
    args = parser.parse_args(argv)
    if args.command == "run":
        return run(args.run, signer=args.sign, identity=args.identity)
    return check(
        args.run, sigstore_identity=args.sigstore_identity, sigstore_issuer=args.sigstore_issuer
    )


if __name__ == "__main__":
    sys.exit(main())
