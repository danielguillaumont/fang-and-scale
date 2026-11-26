# Fang & Scale

Unit tests for breach blast radius in Microsoft Entra and Azure.

Declare what a compromised workload or agent identity must never reach and what it
must still do. Fang & Scale attacks the boundary, proposes the smallest fix, proves
it with signed evidence, and fails CI if it regresses.

> Status: M1 (lab + contracts) in progress. See `docs/PLAN.md` and `docs/milestones/M1.md`.

## Development

Requires [uv](https://docs.astral.sh/uv/). Works on Windows, macOS and Linux.

```
uv run poe setup    # install deps and pre-commit hooks
uv run poe check    # ruff + mypy + import boundaries + pytest
uv run fns --help
```

## License

Apache-2.0. See `LICENSE`.
