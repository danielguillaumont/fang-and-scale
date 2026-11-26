# Contributing

Thanks for your interest. Issues and pull requests are welcome. Report security
problems privately instead: see [SECURITY.md](SECURITY.md).

## Setup

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). It works on Windows,
macOS and Linux.

```
uv run poe setup   # uv sync --all-groups --all-extras, then pre-commit hooks
uv run poe check   # ruff, mypy --strict, import boundaries, schema drift, pytest
```

`uv run poe check` must pass before every commit, and CI runs it on ubuntu and
windows. You need no Azure tenant: every test runs on fixtures and mocks.

## Rules every change keeps

- **Read-only by default.** Only `strike` and `harden --apply` may write, only to
  the lab, and only after `--approve <plan-hash>`. Do not add another write path.
- **Every Azure and Graph call goes through `fns.scope.gate`.** A change to the
  gate needs a negative test.
- **Never claim more than the evidence.** A finding carries its evidence rung and
  coverage state; unsupported semantics give `inconclusive`, never `pass`.
- **The verifier stays separate.** `fns.verify` never imports prover, probe or
  executor code (enforced by import-linter).
- **No secrets and no real tenant IDs** in the repository. Fixtures use
  placeholder GUIDs (`00000000-0000-4000-8000-…`), and a test checks them. Anything
  replayed from `fixtures/` prints `FIXTURE`.
- **Deterministic output.** Sort keys and lists, so digests and snapshots are
  stable.

## Pull requests

- Keep them small, with tests in the same PR.
- Use conventional commit messages (`feat:`, `fix:`, `test:`, `docs:`).
- Add a row to `docs/DECISIONS.md` for any non-trivial choice.
- If a Microsoft API behaves differently from its documentation, record it in
  `docs/FINDINGS.md` with the sanitized request, the response and the date.
- Live runs against a lab tenant are done by the maintainer, never by CI.

By contributing, you agree that your contribution is licensed under the
Apache-2.0 licence of this repository.
