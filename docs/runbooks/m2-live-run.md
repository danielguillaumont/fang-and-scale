# M2 live run: resource settings, PIM eligibility, contract v2 and the `fns contain` gate

This run records a new snapshot, then runs `fns contain` and `fns mutate`
against it. The snapshot now includes:

- Key Vault and storage settings (C1);
- PIM eligibility, or evidence that the tenant has no PIM (M3 E1).

The contract is the seeded **version 2** contract. It also guards the
`id-verifier` and `sp-fns-scout` applications and the invoice account's keys.

Terraform makes one change in Entra: it grants the scout one more Graph read
permission (step 2). Apart from that, the only thing created is a short-lived
certificate on the scout (step 3), which step 7 deletes. The tool itself only
makes GET requests.

All commands are Windows PowerShell, run from the repository root. Use the lab
from M1, which is still running. Keep it running afterwards, because M3 uses
it.

## What this run changes

| Where | Change |
| --- | --- |
| `scope.lab.yaml` (local, gitignored) | Re-rendered with **17** scout operations instead of 12. The five new ones are listed below this table |
| `contracts/lab/billing-agent.fns.yaml` (local, gitignored) | New: the seeded contract, `version: 2`, with your lab's real names (decision D5) |
| Entra | `sp-fns-scout` gets Graph **LicenseAssignment.Read.All** (application, read-only), so it can read `/subscribedSkus` |
| Entra (temporary) | Step 3 adds a certificate credential to `sp-fns-scout` (2 days); step 7 removes it |
| Azure RBAC | None. Reader on the subscription already covers the vault, storage and eligibility reads |

The five new scout operations:

- `arm:Microsoft.KeyVault/vaults/read` and `arm:Microsoft.Storage/storageAccounts/read` (C1);
- `arm:Microsoft.Authorization/roleEligibilitySchedules/read`,
  `graph:GET /roleManagement/directory/roleEligibilitySchedules` and
  `graph:GET /subscribedSkus` (PIM).

**Why `LicenseAssignment.Read.All` when the scout already has `Directory.Read.All`.**

- **Not needed today.** `Directory.Read.All` already covers `/subscribedSkus`, so
  for this run the new grant adds no access.
- **Needed later.** It is the one grant in the reduced set that keeps
  `/subscribedSkus` readable once `scout_directory_read_all = false` drops
  `Directory.Read.All`. Neither `Application.Read.All` nor
  `RoleManagement.Read.Directory` covers that call.
- **What happens without it.** The licence check fails, so `pim-eligibility` can
  never be `not-applicable`. In a tenant without PIM no `must_not_reach` item
  could then pass.

The reasoning is in `docs/DECISIONS.md`.

## 1. Update your checkout

```powershell
git switch main
git pull
uv sync --all-groups
uv run poe check
```

`poe check` must pass before you continue.

## 2. Apply the lab changes (you approve the apply)

```powershell
az login --tenant <TENANT_ID>
az account set --subscription <SUBSCRIPTION_ID>
uv run poe lab-check
uv run poe lab-up
```

Review the plan before typing `yes`. It should show **3 to add, 0 to change, 1
to destroy**, and nothing else:

| Resource | Action | Why |
| --- | --- | --- |
| `local_file.scope` | replaced (1 add, 1 destroy) | it now lists 17 operations |
| `local_file.contract` | added | the v2 lab contract |
| `azuread_app_role_assignment.scout_graph["LicenseAssignment.Read.All"]` | added | lets the scout read `/subscribedSkus` |

If the plan touches anything else, type `no` and send the plan output.

The account that applies needs the same rights as in M1 to grant Graph
application permissions (Privileged Role Administrator or Global
Administrator).

The scope expires 7 days after the lab was created (2026-12-03 for the first
lab). If `fns scope check` below reports it expired, renew it:

```powershell
terraform -chdir=lab apply -replace=time_offset.scope_expiry
```

Check the result:

```powershell
uv run fns scope check scope.lab.yaml           # 17 scout operations, not expired
Get-Content contracts\lab\billing-agent.fns.yaml
```

The contract must start with `version: 2` and name these targets:

- `kv-crown-<suffix>`, `stpayroll<suffix>` and `stinvoices<suffix>`;
- `application: id-verifier` and `application: sp-fns-scout`, each with
  `[credentials/update, owners/update]`.

`stinvoices<suffix>` must appear twice: under `must_not_reach` with
`[listKeys]`, and under `must_still_do` with `[blob/read, blob/write]`.

Optional: check whether the tenant has a PIM licence. You are still signed in
as yourself at this point. Then you know which outcome to expect in step 4.

```powershell
az rest --method get --url "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=skuPartNumber,capabilityStatus" --query "value[].[skuPartNumber,capabilityStatus]" -o tsv
```

PIM comes with Entra ID P2. Look for SKUs such as `AAD_PREMIUM_P2`, `EMSPREMIUM`,
`SPE_E5` or `ENTRA_ID_GOVERNANCE`, or a P2 trial. A free tenant shows none of
these, or no SKUs at all.

## 3. Sign in as the read-only scout

These are the same commands as M1 runbook step 5. Sign in **after** step 2, so
that the scout's token carries the new permission.

```powershell
$tenant = az account show --query tenantId -o tsv
$appId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
$end = (Get-Date).AddDays(2).ToString("yyyy-MM-dd")
$cred = az ad app credential reset --id $appId --create-cert --end-date $end --append | ConvertFrom-Json
Start-Sleep -Seconds 180                         # new certificates take ~3 minutes (FINDINGS)
az login --service-principal --username $appId --certificate $cred.fileWithCertAndPrivateKey --tenant $tenant
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table
```

`type` must be `servicePrincipal`. If the login fails with `AADSTS700027`,
wait another 3 minutes and repeat only the `az login --service-principal` line.

## 4. Scout twice and record `lab-run-2`

```powershell
uv run fns scout --scope scope.lab.yaml --record fixtures/lab-run-2
uv run fns scout --scope scope.lab.yaml
```

Check:

- The `digest sha256:` lines of the two runs are identical.
- The Collectors table has **12** rows. The 11 from before are all `complete`,
  including `arm.resource-settings` with 3 items (one vault, two storage
  accounts).
- The new 12th row, `pim.eligibility`, is in one of the states below.
- `not collected` no longer lists `key-vault-access-policies`.

The `pim.eligibility` row:

| Your tenant | Expected row | Expected `pim-eligibility` |
| --- | --- | --- |
| Has PIM (P2 or a trial) | `complete` | gone from `not collected`. The lab creates no eligible assignments, so there are no `hasEligibleRole` edges unless your tenant already had some for these service principals |
| No PIM licence, and the eligibility listing fails | `not-applicable` | listed under `not applicable in this tenant (evidence):`, with one line per listing (status and error code) and one line for `/subscribedSkus` (SKUs found, "plans that may carry PIM: none") |
| No PIM licence, but both listings return an empty list | `complete` | gone from `not collected`. That is also a valid result |
| Anything else | `partial` or `failed` | still under `not collected`, and the reason says what is missing. Report it |

If the row is `not-applicable`, capture the full error the directory listing
returns. This is a FINDINGS entry: what Graph says to a tenant without P2. You
are still signed in as the scout:

```powershell
az rest --method get --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules" 2>&1 | Out-String
```

Then check the recorded set:

```powershell
uv run pytest tests/fixtures/test_no_real_ids.py -q
git status --short fixtures/lab-run-2          # _idmap.json must NOT be listed
```

## 5. Run `fns contain` on the live snapshot (the M2 gate)

```powershell
$snap = (Get-ChildItem .fns\snapshots\*.LIVE.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
uv run fns contain --contract contracts\lab\billing-agent.fns.yaml --snapshot $snap --alternatives 1
$LASTEXITCODE                                    # expected: 1
```

Expected verdicts. These are the same as on the v2 `lab-run-1` fixture, but now
without assumed defaults:

| Item | Verdict | Final hop |
| --- | --- | --- |
| `kv-crown-<suffix>` `secrets/get`, `secrets/list` | `fail` | `kv-control-to-data` (Contributor on the RG) |
| `stpayroll<suffix>` `listKeys` | `fail` | `rbac-action` |
| `stpayroll<suffix>` `blob/read` | `fail` | `listkeys-data`, with no "not collected" assumption, because shared keys are on |
| `stinvoices<suffix>` `listKeys` | `fail` | `rbac-action` (new in v2) |
| `directory:tenant` `roleAssignments/write` | `fail` | `graph-permission`, via owner, then credential, then self-grant |
| `directory:tenant` `applications/credentials/update` | `fail` | `owned-object-permission` |
| `application:id-verifier` `credentials/update`, `owners/update` | `fail` | `graph-permission`, via the same self-grant of `Application.ReadWrite.All` (new in v2) |
| `application:sp-fns-scout` `credentials/update`, `owners/update` | `fail` | `graph-permission`, the same way (new in v2) |
| `stinvoices<suffix>` `blob/read`, `blob/write` (must still do) | `inconclusive` | allowed in the model (D1) |

The summary line should read `critical reachable: 11/0 max`, and the result
`contract FAILED (exit 1)`.

PIM does not change these verdicts. Every `must_not_reach` item fails on its
own. PIM matters after hardening, when an item could pass. A finding stays
inconclusive on PIM in two cases:

- `pim-eligibility` is still under `not collected`;
- the agent is eligible for a role, in which case its reasons say "is eligible
  (PIM) for …".

Replay the recorded set the same way. Every line should say FIXTURE:

```powershell
Copy-Item contracts\lab\billing-agent.fns.yaml fixtures\lab-run-2\contract.fns.yaml
uv run fns demo contain --fixture fixtures/lab-run-2
$LASTEXITCODE                                    # expected: 1
```

The copied contract holds names only, no IDs. It is what lets the fixture be
committed as a regression test.

## 6. Mutation score on the live snapshot (read-only, in the model)

```powershell
uv run fns mutate --contract contracts\lab\billing-agent.fns.yaml --snapshot $snap --lab lab --harden --max-survivors 2
$LASTEXITCODE                                    # expected: 0 (2 survivors, 2 allowed)
```

Expected result: `Mutation score 6/8`, the same as `fns demo mutate`, and
`2 survivor(s), within the allowed 2`.

There are eight mutants:

- Owner on the resource group (1);
- the Storage Account Key Operator role on each storage account (2);
- three privileged Graph permissions (3);
- ownership of each application the agent does not already own (2).

`remove-deny-assignment` shows as `n/a`. It is not a survivor and is not counted:
the lab has no deny assignment to remove. Azure creates deny assignments only for
managed applications and deployment stacks, and the lab uses neither.

**Killed (6):** `owner-at-rg:rg-fns-lab`, both `listkeys:` mutants, and the
three `graph-app-permission:` mutants.

**Survived (2), accepted and explained:** `app-owner:id-verifier` and
`app-owner:sp-fns-scout`.

- **What they do.** Each mutant makes the agent an owner of that application.
- **Why nothing is reached.** `--harden` has removed the agent's
  `Application.ReadWrite.OwnedBy`, and the agent never had
  `Application.ReadWrite.All`. An app-only caller needs one of those two Graph
  permissions to add a credential to an application it owns, or to change that
  application's owners. Ownership alone therefore reaches none of the forbidden
  operations. The output says so: "owns id-verifier but holds neither
  Application.ReadWrite.OwnedBy nor Application.ReadWrite.All ... (one Graph
  grant away)".
- **Why no contract change kills them.** `must_not_reach` lists operations, and
  ownership alone lets the agent perform none of them. Killing these mutants
  would need a new kind of check that fails on the ownership itself (option (b)
  in `docs/DECISIONS.md`), not another contract line.
- **Why the attack is still covered.** The other half of the attack is the Graph
  grant, and the three `graph-app-permission:` mutants already catch it.

`--max-survivors 2` allows a count of survivors, not specific names. Check that
the two `SURVIVED` lines are exactly the two above. Any other survivor is a
regression: report it in step 8.

The claim that ownership is unusable without `OwnedBy` comes from Microsoft's
documentation. It is modeled, not yet observed in this lab.

This changes nothing in the tenant: `--harden` applies the proposal in the model
only.

## 7. Remove the scout certificate

These are the same commands as M1 runbook step 8.

```powershell
az login --tenant $tenant
az ad app credential list --id $appId --cert --query "[].{keyId:keyId, end:endDateTime}" -o table
az ad app credential delete --id $appId --key-id <keyId> --cert
Remove-Item $cred.fileWithCertAndPrivateKey
az ad app credential list --id $appId --cert -o table      # should be empty
```

Leave `LicenseAssignment.Read.All` in place: it is part of the lab now.

## 8. Report back

Send:

- **Step 2:** the Terraform plan summary line, and whether the tenant has a PIM
  licence (the optional `subscribedSkus` output).
- **Step 4:**
  - both scout digests and the Collectors table;
  - the `not collected` and `not applicable` blocks;
  - if `pim.eligibility` is `not-applicable`, the raw error from the `az rest`
    call;
  - the result of `test_no_real_ids`.
- **Step 5:** the `fns contain` summary line, the exit code, and the Findings
  block.
- **Step 6:** the mutation score line, the exit code, and the names and reasons
  of the survivors.
- Anything that differed from the tables above.

With that, the next steps are:

- commit `fixtures/lab-run-2`, with its `contract.fns.yaml`, as the C4
  regression test;
- record the PIM responses and any other API differences in `docs/FINDINGS.md`;
- tag `m2`.

## Troubleshooting

- **`arm.resource-settings` is `partial` with `http-403`:** the scout identity
  cannot read the vault or account. Reader on the subscription should cover
  `Microsoft.KeyVault/vaults/read` and `Microsoft.Storage/storageAccounts/read`.
  Report the exact error. It is a finding: record it in `docs/FINDINGS.md`.
- **`pim.eligibility` says `GET /subscribedSkus -> http-403`:** the new
  permission is not in the scout's token yet. Wait a few minutes, sign in as the
  scout again (step 3, `az login` line only), and scout again. If it persists,
  report it, and record it in FINDINGS if Microsoft's documented permission is
  not enough.
- **`pim.eligibility` is `partial` and the reason lists "licences that may carry
  PIM":** the tenant has a PIM licence, but an eligibility listing failed. The
  reason names the listing, its status and its error code. Report it. It is not
  `not-applicable`, by design.
- **The ARM eligibility listing fails with `http-400` and an API-version
  error:** report the error. The collector uses `api-version=2020-10-01`.
- **`foreign-tenant-policy` in the error codes:** a vault access policy names a
  principal from another tenant. The lab creates none, so report it.
- **The plan in step 2 shows other changes:** type `no`. Something drifted since
  M1; send the plan output.
