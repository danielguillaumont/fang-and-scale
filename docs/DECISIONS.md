# Decision log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-11-25 | Entra/Azure-first; AWS is a later adapter | Microsoft-heavy target roles; SC-200 alignment |
| 2026-11-25 | Absorb K9 ideas (coverage states, hypotheses, scope manifest); retire the K9 name | One complete flagship; k9 Security already sells Azure IAM analysis |
| 2026-11-25 | Module name Antivenom (not Defang) | Defang is an existing company |
| 2026-11-25 | Python only, SQLite, static report for v0.1 | Ship the loop before the infrastructure |
| 2026-11-25 | Workload/agent identities are the wedge | Less crowded than generic attack-path graphs |
| 2026-11-25 | poethepoet tasks in `pyproject.toml` (`uv run poe <task>`) instead of a Makefile | Dev on native Windows, CI on Linux; poe `cmd` tasks run without a shell |
| 2026-11-25 | `.gitattributes` `* text=auto eol=lf`; code writes files with `newline="\n"` | Committed schemas/fixtures must be byte-identical on Windows and Linux |
| 2026-11-25 | CI matrix ubuntu-latest + windows-latest; actions pinned by commit SHA | Catches path/newline/SQLite-locking bugs on the dev OS; supply-chain hygiene |
| 2026-11-25 | Rule 2 enforced by ruff `TID251` (Azure SDK imports only in `fns.adapters`, `fns.scope.credentials`) | Mechanical check instead of convention |
| 2026-11-25 | Rule 5 enforced by import-linter: `fns.verify` may not import `fns.harden`, `fns.strike`, `fns.adapters` (transitive) | Trust boundary checked from day one; empty `strike`/`harden` packages exist so the contract resolves |
| 2026-11-25 | `ExitCode` enum; not-implemented = 2 per M1 spec (shares Click's usage-error code) | One place to change if CI needs to tell them apart |
| 2026-11-25 | No Azure SDK or NetworkX deps in Phase A | Smaller surface until they are used (Phase B / M2) |
| 2026-11-25 | License Apache-2.0 (Daniel's decision) | Permissive with a patent grant |
| 2026-11-25 | PRs merged with merge commits (not squash); branch deleted after merge | Keeps the small conventional commits from each sub-step |
