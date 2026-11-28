# Scenario gallery (FIXTURE)

Five small, hand-written tenants with a common Entra or Azure misconfiguration
each. **Every one is a FIXTURE**: no tenant was called, the GUIDs are
placeholders (`00000000-0000-4000-8000-…`), and every output line is labelled
`FIXTURE`. They show what the tool says about a pattern; they are not evidence
about any real tenant, and the newer collectors they use (credential metadata,
federated credentials, transitive memberships) are **not yet validated live**
(`docs/runbooks/live-validation-backlog.md`).

Each scenario has two tenants, `tenant/` (the misconfiguration) and `fixed/`
(after the smallest fix), and the output of `fns demo contain` for both. Each
`tenant/` and `fixed/` folder is a replayable fixture set: the real scope gate,
collector and reach model run on it, only the transport is a replay.

| # | Scenario | Before the fix | After the fix |
| --- | --- | --- | --- |
| 1 | [The agent owns a privileged application](01-owner-of-privileged-app/README.md) | FAIL `kv-crown secrets/get` (exit 1) | within budget (exit 0) |
| 2 | [Contributor flips the vault to access policies](02-contributor-key-vault-flip/README.md) | FAIL `kv-crown secrets/get`, `secrets/list` (exit 1) | within budget (exit 0) |
| 3 | [listKeys is data access](03-listkeys-is-data-access/README.md) | FAIL `stpayroll blob/read`, `blob/write` (exit 1) | within budget (exit 0) |
| 4 | [A GitHub trust that accepts every pull request](04-github-trust-too-broad/README.md) | within budget, front door **high** (exit 0) | within budget, front door **medium** (exit 0) |
| 5 | [A nested group makes the agent Owner](05-nested-group-owner/README.md) | FAIL `kv-crown secrets/get`, `roleAssignments/write` (exit 1) | within budget (exit 0) |

"Within budget" is never "pass": with modeled evidence only, a target the
model does not reach is `inconclusive`, and the contract's `max_inconclusive`
accepts it. `fns prove` (live) is what can raise a finding to `pass`.

## Run one

```powershell
uv run fns demo contain --fixture docs/scenarios/01-owner-of-privileged-app/tenant
uv run fns demo contain --fixture docs/scenarios/01-owner-of-privileged-app/fixed
```

## How they are built

`scripts/build_scenarios.py` holds each tenant as a short spec (principals,
groups, grants, resources). A fake tenant answers the scout's requests from
it, the real collector records them, and the script writes the fixture sets
and the `expected-*.txt` outputs. `tests/test_scenarios.py` fails if any
committed file or output drifts:

```powershell
uv run python scripts/build_scenarios.py --check
```
