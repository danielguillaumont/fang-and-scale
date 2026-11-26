# Fang & Scale

Unit tests for breach blast radius in Microsoft Entra and Azure.

Declare what a compromised workload or agent identity must never reach and what it
must still do. Fang & Scale attacks the boundary, proposes the smallest fix, proves
it with signed evidence, and fails CI if it regresses.

> Status: M1 (lab + contracts). See `docs/PLAN.md` and `docs/milestones/M1.md`.

## What M1 does

- **Contracts and scope as data.** `contracts/*.fns.yaml` says what an identity must
  never reach; `scope.yaml` says what the tool itself may touch. Both have JSON
  Schemas in `schemas/`.
- **A deny-by-default scope gate.** Every Azure and Graph request, page and retry
  passes `fns.scope.gate`: tenant pinning, expiry, operation allowlist, resource
  group boundaries, call and time budgets. Writes are refused in M1.
- **`fns scout`**: a read-only snapshot of RBAC role assignments and definitions,
  deny assignments, resources, service principals, applications, owners, Graph app
  role assignments, directory roles and group memberships. Collection failures
  are recorded as coverage gaps, never hidden. The snapshot digest is
  deterministic: same tenant state, same digest.
- **Fixtures.** `--record` saves sanitized responses; `fns demo scout` replays them
  with every output line labelled `FIXTURE`.

## Try it without a tenant

```
uv run poe demo        # or: uv run fns demo scout
```

This replays the bundled demo tenant (placeholder IDs) through the real gate,
collector and journal. The snapshot is written to `.fns/snapshots/`.

## Development

Requires [uv](https://docs.astral.sh/uv/). Works on Windows, macOS and Linux.

```
uv run poe setup      # install deps and pre-commit hooks
uv run poe check      # ruff + mypy + import boundaries + schema drift + pytest
uv run poe lab-check  # terraform fmt -check + validate (no credentials needed)
uv run fns --help
```

## Lab and live scout

`lab/` is a Terraform lab (azurerm + azuread) for a **dedicated lab tenant**: an
over-privileged `sp-billing-agent`, a Key Vault and storage with synthetic data, a
privileged `app-escalation-target` owned by the agent, a read-only `id-verifier`,
and the read-only `sp-fns-scout` identity. `uv run poe lab-up` applies it and writes
`scope.lab.yaml` (gitignored); `uv run poe lab-down` destroys it. Terraform refuses
to run if the signed-in tenant differs from `tenant_id`.

```
uv run poe scout                                       # live, read-only
uv run fns scout --record fixtures/lab-run-1          # also save a sanitized fixture set
uv run fns demo scout --fixture fixtures/lab-run-1    # replay it later, no tenant needed
```

`fns scout` signs in through the Azure CLI (`az login`). Fang & Scale never reads,
stores or asks for a secret. Before the first request it checks that the token was
issued for the tenant in the scope manifest and stops if not (exit 4).

### Scout permissions

The scout identity (`sp-fns-scout`) gets exactly the following, and nothing that
can write:

| Grant | Scope | Used for |
| --- | --- | --- |
| Azure RBAC **Reader** | lab subscription | `roleAssignments/read`, `roleDefinitions/read`, `denyAssignments/read`, `resourceGroups/resources/read`, and (M2) `Microsoft.KeyVault/vaults/read` and `Microsoft.Storage/storageAccounts/read` for vault access policies, permission model and shared-key setting |
| Graph **Application.Read.All** (application) | tenant | `/servicePrincipals`, `/applications`, their `/owners`, `/servicePrincipals/{id}/appRoleAssignments` |
| Graph **RoleManagement.Read.Directory** (application) | tenant | `/roleManagement/directory/roleDefinitions` and `/roleAssignments` |
| Graph **Directory.Read.All** (application) | tenant | `/servicePrincipals/{id}/memberOf`, and resolving owners and members that are users or groups |

Why this set:

- **Reader** is `*/read` only. It cannot run actions, so no `listKeys`, and it has
  no data-plane access, so no secrets or blobs. Every ARM call scout makes is a
  `read` operation.
- **Application.Read.All** and **RoleManagement.Read.Directory** are the
  least-privileged Graph permissions documented for those endpoints.
- **Directory.Read.All** is the broadest grant here: read access to the whole
  directory. It is included because membership and owner objects of type user or
  group are not fully returned with `Application.Read.All` alone. The first live
  run (2026-11-26) showed the set is sufficient: scouting as `sp-fns-scout` gave
  the same digest as scouting as the lab admin. Whether `Directory.Read.All` can
  be dropped is the next live test (`docs/FINDINGS.md`).
- Not granted: anything `ReadWrite`, `Policy.Read.All` (Conditional Access is not
  collected in M1), audit or sign-in logs, and Key Vault or Storage data roles.

The scope manifest narrows this further: the gate allows only the 12 read
operations listed in `scope.lab.yaml` (14 since M2), only within the lab subscription and
resource group, within a call and time budget, and only until `expires_at`.

## License

Apache-2.0. See `LICENSE`.
