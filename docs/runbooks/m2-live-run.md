# M2 live run: resource settings (C1) and the `fns contain` gate (C4)

This run records a new snapshot that includes Key Vault and storage settings,
then runs `fns contain` against it. Nothing is created in Azure except a
short-lived certificate on the scout (step 3), which step 6 deletes. The tool
itself only makes GET requests.

All commands are Windows PowerShell, run from the repository root. Use the lab
from M1, which is still running. Keep it running afterwards, because M3 uses
it.

## What this run changes

| Where | Change |
| --- | --- |
| `scope.lab.yaml` (local, gitignored) | Re-rendered with 14 scout operations instead of 12: `arm:Microsoft.KeyVault/vaults/read` and `arm:Microsoft.Storage/storageAccounts/read` are new |
| `contracts/lab/billing-agent.fns.yaml` (local, gitignored) | New: the seeded contract with your lab's resource names (decision D5) |
| Azure and Entra | Nothing from Terraform. Step 3 adds a certificate credential to `sp-fns-scout` (2 days); step 6 removes it |
| Permissions | None new. `sp-fns-scout` keeps Reader on the subscription, and Reader covers both new reads |

## 1. Update your checkout

```powershell
git switch main
git pull
uv sync --all-groups
uv run poe check
```

`poe check` must pass before you continue.

## 2. Re-render the local scope and contract files (you approve the apply)

```powershell
az login --tenant <TENANT_ID>
az account set --subscription <SUBSCRIPTION_ID>
uv run poe lab-check
uv run poe lab-up
```

Review the plan before typing `yes`. It should show **2 to add, 0 to change, 1
to destroy**, and every line should be a `local_file`:

- `local_file.scope` is replaced, because its content now lists 14 operations.
- `local_file.contract` is added.

If the plan touches anything in Azure, type `no` and report it.

The scope expires 7 days after the lab was created (2026-12-03 for the first
lab). If `fns scope check` below reports it expired, renew it:

```powershell
terraform -chdir=lab apply -replace=time_offset.scope_expiry
```

Check the result:

```powershell
uv run fns scope check scope.lab.yaml           # 14 scout operations, not expired
Get-Content contracts\lab\billing-agent.fns.yaml
```

The contract should name `kv-crown-<suffix>`, `stpayroll<suffix>` and
`stinvoices<suffix>`.

## 3. Sign in as the read-only scout

These are the same commands as M1 runbook step 5.

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
- The Collectors table has 11 rows, all `complete`, including
  `arm.resource-settings` with 3 items (one vault, two storage accounts).
- `not collected` no longer lists `key-vault-access-policies`.

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

Expected verdicts. These are the same as on `lab-run-1`, but now without
assumed defaults:

| Item | Verdict | Final hop |
| --- | --- | --- |
| `kv-crown-<suffix>` `secrets/get`, `secrets/list` | `fail` | `kv-control-to-data` (Contributor on the RG) |
| `stpayroll<suffix>` `listKeys` | `fail` | `rbac-action` |
| `stpayroll<suffix>` `blob/read` | `fail` | `listkeys-data`, with no "not collected" assumption, because shared keys are on |
| `directory:tenant` `roleAssignments/write` | `fail` | `graph-permission`, via owner, then credential, then self-grant |
| `directory:tenant` `applications/credentials/update` | `fail` | `owned-object-permission` |
| `stinvoices<suffix>` `blob/read`, `blob/write` | `inconclusive` | allowed in the model (D1) |

The summary line should read `critical reachable: 6/0 max`, and the result
`contract FAILED (exit 1)`.

Replay the recorded set the same way. Every line should say FIXTURE:

```powershell
Copy-Item contracts\lab\billing-agent.fns.yaml fixtures\lab-run-2\contract.fns.yaml
uv run fns demo contain --fixture fixtures/lab-run-2
$LASTEXITCODE                                    # expected: 1
```

The copied contract holds resource names only, no IDs. It is what lets the
fixture be committed as a regression test.

## 6. Remove the scout certificate

These are the same commands as M1 runbook step 8.

```powershell
az login --tenant $tenant
az ad app credential list --id $appId --cert --query "[].{keyId:keyId, end:endDateTime}" -o table
az ad app credential delete --id $appId --key-id <keyId> --cert
Remove-Item $cred.fileWithCertAndPrivateKey
az ad app credential list --id $appId --cert -o table      # should be empty
```

## 7. Report back

Send:

- both scout digests from step 4, and the Collectors table;
- the `fns contain` summary line, the exit code, and the Findings block from step 5;
- the result of `test_no_real_ids` from step 4;
- anything that differed from the tables above.

With that, the next steps are to commit `fixtures/lab-run-2` (with its
`contract.fns.yaml`) as the C4 regression test, record API differences in
`docs/FINDINGS.md`, and tag `m2`.

## Troubleshooting

- **`arm.resource-settings` is `partial` with `http-403`:** the scout identity
  cannot read the vault or account. Reader on the subscription should cover
  `Microsoft.KeyVault/vaults/read` and `Microsoft.Storage/storageAccounts/read`.
  Report the exact error. It is a finding: record it in `docs/FINDINGS.md`.
- **`foreign-tenant-policy` in the error codes:** a vault access policy names a
  principal from another tenant. The lab creates none, so report it.
- **The plan in step 2 shows Azure changes:** type `no`. Something drifted since
  M1; send the plan output.
