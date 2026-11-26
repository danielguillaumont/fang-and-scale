# Fang & Scale

Unit tests for breach blast radius in Microsoft Entra and Azure. Declare what a
compromised workload/agent identity must never reach and what it must still do;
the tool attacks the boundary, proposes the smallest fix, proves it with signed
evidence, and fails CI if it regresses.

- Full product plan: `docs/PLAN.md` (read before any design decision)
- Current milestone spec: `docs/milestones/M1.md`
- Decisions: `docs/DECISIONS.md` (append a row for every non-trivial choice)

## Non-negotiable rules

1. **Read-only by default.** Only `strike` and `harden --apply` may write, only to
   the lab, only after `--approve <plan-hash>`. Never add a write path anywhere else.
2. **Every Azure/Graph call goes through `fns.scope.gate`.** No adapter may call an
   SDK client directly. A missing, expired or mismatched scope field means deny.
3. **Tenant pinning.** Abort if the signed-in tenant differs from `scope.yaml`.
4. **Never claim more than the evidence.** Every finding carries an evidence rung
   (modeled / evaluated / observed / logged) and a coverage state. Unsupported
   semantics return `inconclusive`, never `pass`.
5. **The verifier never imports proposer or executor code.** Keep the trust
   boundary physical: separate package `fns.verify`, separate credentials.
6. **No secrets in the repo.** No client secrets, no real tenant IDs in fixtures
   (use placeholder GUIDs), no `.env` committed. CI uses OIDC federation.
7. **Fixtures are labelled.** Anything replayed from `fixtures/` prints `FIXTURE`.
8. **No AI attribution.** Do not add Co-Authored-By trailers, "Generated with"
   lines, or Claude as a contributor in commits, PRs, README or changelogs.

## Stack

Python 3.12, uv, Typer + Rich, Pydantic v2, azure-identity, azure-mgmt-authorization,
azure-mgmt-resource, msgraph-sdk, NetworkX, SQLite (stdlib), Terraform (azurerm +
azuread), pytest + hypothesis, ruff, mypy --strict.

## Commands

- `make setup`  install deps with uv, install pre-commit hooks
- `make check`  ruff + mypy + pytest (must pass before every commit)
- `make lab-up` / `make lab-down`  apply / destroy the Terraform lab
- `uv run fns --help`

## Working style

- Plan first for anything touching scope, contracts, the evidence model or the
  verifier; show the plan and wait for approval.
- Small commits, conventional commit messages (`feat:`, `fix:`, `test:`, `docs:`).
- Tests come with the code, not after. Scope-gate changes need a negative test.
- Deterministic output: sort keys and lists so snapshots and digests are stable.
- When a Microsoft API behaves differently than documented, record it in
  `docs/FINDINGS.md` with the request, response and date. These are features.
