# Findings: Microsoft API behaviour vs documentation

Record every case where ARM or Graph behaves differently than documented: the
request (sanitized), the response, the date, and what the code does about it.

| Date | API | Request | Documented | Observed | Handling |
| --- | --- | --- | --- | --- | --- |
| 2026-11-26 | ARM (Azure Policy) | `terraform apply` creating `rg-fns-lab` with `location = "eastus"` on an Azure for Students subscription | Any public region can be used for a resource group | Denied by the built-in assignment "Allowed resource deployment regions". Allowed on this subscription: `belgiumcentral`, `northcentralus`, `norwayeast`, `westus`, `canadacentral`. List with `az policy assignment list --query "[].{name:displayName, allowed:parameters.listOfAllowedLocations.value}"` | `location` is now a required Terraform variable with no default; runbook step 3 lists the allowed regions first, and step 4 has a troubleshooting entry |
| 2026-11-26 | ARM (`Microsoft.KeyVault/vaults` PUT, `canadacentral`) | azurerm 5.15.0 creating `kv-crown-<suffix>`, then polling the long-running operation | Polling returns the operation status until the vault is provisioned | A polling GET returned **404** and Terraform failed, but the vault had been created. It was then missing from state, and a re-apply failed because the name was taken | Recovered with `terraform import azurerm_key_vault.crown_jewels <vault id>`, then apply. Runbook step 4, "Troubleshooting". Not retried automatically: the tool never applies Terraform |
| 2026-11-26 | Entra ID token endpoint (client credentials, certificate) | `az login --service-principal --certificate <pem>` right after `az ad app credential reset --create-cert --append` on `sp-fns-scout` | A new credential is usable once the reset call returns | First sign-in failed with `AADSTS700027` (invalid signature on the client assertion); the same command worked about 3 minutes later with no change | Runbook step 5: wait 3 minutes and retry the login; do not create a second certificate. Live collectors use the existing CLI session, so no code change |

## First live run (2026-11-26)

- Two scouts as the lab admin gave the same digest
  (`sha256:463a3c058ef43bdabf5ea4d647c69405274c4b56b0fc628c0088b3d8e37d2c66`).
  All 10 collectors were `complete`: 210 entities, 31 edges, 28 gated calls.
- A third scout signed in as `sp-fns-scout` (Reader on the subscription;
  Application.Read.All, RoleManagement.Read.Directory, Directory.Read.All) gave
  the **same digest**, with every collector `complete`.
- The first run was recorded and sanitized as `fixtures/lab-run-1`.
  `tests/fixtures/test_no_real_ids.py` passed, and the replay digest is pinned in
  `tests/golden/lab-run-1.digest`.

## Mutation testing found a gap in our own contract (2026-11-26)

Not Microsoft behaviour, but a finding about this project's own contract, found
by `fns mutate` (M5) on `fixtures/lab-run-1`, hardened in the model.

- **First run: 5 of 8.** The seeded contract (version 1) missed three mutants:
  - `listKeys` on the invoices account. The contract simply did not forbid it.
  - The agent becoming an owner of `id-verifier`.
  - The agent becoming an owner of `sp-fns-scout`.

  Version 1 could not name one application as a target, so the contract had no
  way to say "the agent must never control the verifier". This was a gap in the
  model, not just a missing line.
- **Fix: contract version 2** (approved in the morning review).
  - `must_not_reach` can name an `application` or a `service_principal`, with
    `credentials/update` and `owners/update`.
  - The seeded contract now forbids both operations on `id-verifier` and
    `sp-fns-scout`, and `listKeys` on the invoices account.
  - A new detection rule, `object-owner-added-by-workload`, covers owner changes.
- **Second run: 6 of 8.**
  - `listKeys` on invoices is killed.
  - Every Graph-permission mutant now also fails the four new items. On the
    unhardened lab, the agent reaches both applications through the self-grant
    chain (owner adds a credential, then `AppRoleAssignment.ReadWrite.All` grants
    `Application.ReadWrite.All`).
  - The two ownership mutants still survive, for a real reason. In the hardened
    lab the agent holds neither `Application.ReadWrite.OwnedBy` nor
    `Application.ReadWrite.All`. An app-only caller cannot use an ownership
    without one of them, so ownership alone adds no reach. The model sees the
    change, and the survivor's output says "owns id-verifier but holds neither
    ... (one Graph grant away)".
- **Accepted (2026-11-26 review).** The two ownership mutants are accepted,
  explained survivors. No contract line can kill them, because ownership alone
  allows none of the forbidden operations. A check that fails on an unusable
  ownership would be a new kind of check, not a contract change. The Graph grant
  that would make the ownership usable is already caught by the three
  Graph-permission mutants.

## Research items (planned, not run)

- **R1. Does ARM authorize before it validates?** If so, a deliberately
  invalid write returns `403` when the caller is denied and `400` when it is
  allowed, which would be a non-mutating authorization probe for writes. The
  plan is in `docs/milestones/M3.md` (R1). No request has been sent; until a
  result is recorded here, writes stay at rung 2 at most (E4).

## Open questions from Phase B

- **Is `Directory.Read.All` needed?** Partly answered. The full set is
  sufficient, but nothing has tested whether it is minimal: the lab's owners are
  one user and three service principals, and no service principal is a member of
  a group. Next live run: apply with `scout_directory_read_all = false` and
  compare (runbook step 9, "Next live run"). Until then it stays in the default.
- **Well-known IDs** (`src/fns/fixtures/wellknown.py`). Checked against the
  tenant's responses, and kept checked by `tests/fixtures/test_lab_fixture.py`.
  Two were wrong, both my errors rather than API behaviour:
  - `APPLICATION_READWRITE_ALL` was `...-73c6d2b2e8db`; the tenant returns
    `1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9`.
  - `KEY_VAULT_SECRETS_OFFICER` (`b86a8fe4-44ce-4948-aee5-eccb2c155cd7`) was
    missing.

  The sanitizer had replaced both with placeholders in the recording. They are
  now on the allowlist and restored verbatim in `fixtures/lab-run-1`. Every other
  RBAC role, Graph app role and directory role template that appears in the lab
  matched.
- **Assignments at `/` or at management groups.** Not exercised. The lab
  subscription's listing returned only subscription and resource-group scopes.
  The handling stays as built; it is covered by unit tests only.
