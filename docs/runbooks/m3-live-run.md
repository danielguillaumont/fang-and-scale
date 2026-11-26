# M3 live run: live probes as the test identity (`fns prove --live`)

This run sends the frozen probes to the lab **as `sp-billing-agent`**, the
identity the contract assumes is compromised. The verifier then checks the
evidence in its own process, with no Azure credential (V1), and signs it with
the offline test key. The run is recorded as `fixtures/lab-run-3`.

Every probe is a `GET` or a `HEAD` through the scope gate. The run sends
**14 requests**:

- 9 `permissions` reads (rung 2);
- 1 ARM metadata read of the synthetic secret (the V6 pre-flight);
- 2 Key Vault `GET`s;
- 2 blob `HEAD`s.

That is 13 distinct probes plus the pre-flight. The contract freezes 17 probe
specs, but 4 of them ask the same question for a second finding, and each
question is sent once.

All commands are Windows PowerShell, run from the repository root. Use the lab
from M1 and M2, which is still running. Do it in one sitting: from the agent
certificate to its deletion (steps 5 to 7) takes about 10 minutes.

**Before you start.**

- PRs #29 to #34 are merged:
  - #29: scope gate;
  - #30: live probes;
  - #31: lab scope;
  - #32: verifier isolation;
  - #33 and #34: Sigstore staging.
- Decisions V1 to V6 are approved (`docs/DECISIONS.md`).
- Nothing in this run touches Sigstore. The `prove-sign` workflow signs in CI,
  on staging only.

If the session dies at any point after a certificate exists, go straight to
[Emergency cleanup](#emergency-cleanup-if-the-session-dies-midway).

## What this run changes

| Where | Change |
| --- | --- |
| `scope.lab.yaml` (local, gitignored) | Re-rendered with a 7-day expiry and these additions: a `prove:` block of **6** read operations, `data_objects` binding each data-plane read to its vault or account, and the agent's `app_id` |
| Key Vault (`kv-crown-<suffix>`) | The synthetic secret `payroll-db-password` gets the tag `fns-data = synthetic`. Its value is unchanged. The probe reads the secret only if it sees this tag (V6) |
| Entra (temporary) | A certificate on `sp-fns-scout`, valid for 1 day at most. Created in step 3, deleted in step 4 |
| Entra (temporary) | A certificate on **`sp-billing-agent`**, valid for 1 day at most. Created in step 5, deleted in step 7 |
| Azure RBAC, Graph permissions | None |

The 6 `prove` operations:

- `arm:Microsoft.Authorization/permissions/read`;
- `arm:Microsoft.KeyVault/vaults/secrets/read` (metadata only, never the value);
- `kv:GET /secrets`;
- `kv:GET /secrets/payroll-db-password`;
- `blob:HEAD /payroll/employees-SYNTHETIC.csv`;
- `blob:HEAD /invoices/invoice-0001-SYNTHETIC.json`.

## 1. Update your checkout

```powershell
git switch main
git pull
uv sync --all-groups --all-extras
uv run poe check
```

`poe check` must pass before you continue.

## 2. Renew the scope and apply the lab changes (you approve the apply)

The scope from M1 expires on **2026-12-03**. A gate refuses every call once the
scope has expired, including a call in the middle of a run. So this apply also
renews it, to 7 days from now, with `-replace=time_offset.scope_expiry`. Keep
the quotes in PowerShell: unquoted, PowerShell does not pass the argument through
intact (the M3 run needed the quotes).

```powershell
az login --tenant <TENANT_ID>
az account set --subscription <SUBSCRIPTION_ID>
$tenant = az account show --query tenantId -o tsv
uv run poe lab-check
terraform -chdir=lab init -input=false
terraform -chdir=lab apply "-replace=time_offset.scope_expiry"
```

Review the plan before typing `yes`. It should show **2 to add, 1 to change, 2
to destroy**, and nothing else:

| Resource | Action | Why |
| --- | --- | --- |
| `time_offset.scope_expiry` | replaced (1 add, 1 destroy) | the renewal: a new 7-day expiry |
| `local_file.scope` | replaced (1 add, 1 destroy) | the new expiry, the `prove:` block, `data_objects` and `app_id` |
| `azurerm_key_vault_secret.payroll_db` | **updated in place** | `tags`: `+ "fns-data" = "synthetic"` |

Under "Changes to Outputs" you will also see `scope_expires_at` change and a new
`billing_agent` output.

If the secret shows **`-/+` (replace)** or a change to `value`, type `no`. The tag
must not create a new secret. If the plan touches anything else, type `no` as
well, and send the plan output.

Check the result:

```powershell
uv run fns scope check scope.lab.yaml
```

- `expires` is about 7 days away.
- The table lists 17 `scout` and 6 `prove` operations, all `read`.
- The test identity line ends with `app_id <guid>`, and that GUID equals
  `(terraform -chdir=lab output -json billing_agent | ConvertFrom-Json).client_id`.
- `data objects 3 (prove reads only these)`, then:
  - the secret on `kv-crown-<suffix>`;
  - the payroll blob on `stpayroll<suffix>`;
  - the invoice blob on `stinvoices<suffix>`.

Then check the tag the way the probe will see it: an ARM read of the secret's
**metadata**. Do not use `az keyvault secret show`, because it returns the value.

```powershell
$vaultId = az keyvault list -g rg-fns-lab --query "[0].id" -o tsv
az rest --method get --url "https://management.azure.com$vaultId/secrets/payroll-db-password?api-version=2023-07-01" --query "{name:name, tags:tags}" -o json
```

`tags` must include `"fns-data": "synthetic"`. If it does not, stop and report
it. If Terraform set the tag but ARM does not show it, that is a FINDINGS entry.

## 3. Fresh scout as `sp-fns-scout`, recorded as `lab-run-3`

The scout signs in under its own temporary CLI profile (`AZURE_CONFIG_DIR`), so
your own login stays untouched in the default profile.

```powershell
$scoutId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$scoutCred = az ad app credential reset --id $scoutId --create-cert --end-date $end --append --display-name fns-m3-scout | ConvertFrom-Json
Start-Sleep -Seconds 180                         # new certificates take ~3 minutes (FINDINGS)

$scoutDir = Join-Path $env:TEMP "fns-scout-az"
New-Item -ItemType Directory -Force $scoutDir | Out-Null
$env:AZURE_CONFIG_DIR = $scoutDir
az login --service-principal --username $scoutId --certificate $scoutCred.fileWithCertAndPrivateKey --tenant $tenant
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table   # type: servicePrincipal, user: $scoutId

uv run fns scout --scope scope.lab.yaml --record fixtures/lab-run-3
$snap = (Get-ChildItem .fns\snapshots\*.LIVE.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

If the login fails with `AADSTS700027`, wait 3 more minutes and repeat only the
`az login --service-principal` line.

Expected: the same 12 collectors as in M2. Eleven are `complete`, and
`pim.eligibility` is `not-applicable` with the same evidence. The digest may
differ from lab-run-2 only if the lab changed. The secret tag is not part of the
snapshot.

## 4. Remove the scout certificate

```powershell
az logout
Remove-Item Env:AZURE_CONFIG_DIR
foreach ($i in 1..5) {   # Windows can hold the profile briefly; in M3 it went 10 s later
    Remove-Item -Recurse -Force $scoutDir -ErrorAction SilentlyContinue
    if (-not (Test-Path $scoutDir)) { break }
    Start-Sleep -Seconds 3
}
Test-Path $scoutDir                                                    # must print False
az account show --query "user.name" -o tsv                        # you again, not the scout
# step 3 checked the list was empty first, so every certificate here is this run's
foreach ($k in @(az ad app credential list --id $scoutId --cert --query "[].keyId" -o tsv)) {
    az ad app credential delete --id $scoutId --key-id $k --cert
}
Remove-Item $scoutCred.fileWithCertAndPrivateKey
az ad app credential list --id $scoutId --cert -o tsv             # must print nothing
```

## 5. Create the `sp-billing-agent` certificate

> [!CAUTION]
> **`sp-billing-agent` is the escalation-capable identity.** It holds
> Contributor on `rg-fns-lab` and `Application.ReadWrite.OwnedBy`, and it owns
> applications. That is the attack path this tool exists to find. While you are
> signed in as it, one wrong `az` command could do any of these:
> - add a credential to an application it owns;
> - change RBAC in the resource group;
> - read storage account keys.
>
> - **The credential is a certificate valid for at most 1 day,** created
>   immediately before the probes (this step) and deleted immediately after
>   them (step 7). Never a client secret.
> - **Check the credential list is empty** before you create it, and again after
>   you delete it.
> - **While signed in as the agent, run only the commands in step 6.** Do not
>   run Terraform, `az role`, `az ad`, `az storage` or `az keyvault`, or any
>   other tool.
> - **Do not copy, move or open the PEM file.** It holds the private key. Step 7
>   deletes it.
> - **If anything goes wrong, or the session dies, go to
>   [Emergency cleanup](#emergency-cleanup-if-the-session-dies-midway) now.** Even
>   if nobody cleans up, the certificate stops working within 24 hours.

You are signed in as yourself, in the default CLI profile.

```powershell
$agentId = (terraform -chdir=lab output -json billing_agent | ConvertFrom-Json).client_id
az ad app credential list --id $agentId --cert -o tsv            # must print nothing
az ad app credential list --id $agentId -o tsv                   # no client secrets either
az ad sp credential list --id $agentId --cert -o tsv             # nothing on the service principal
```

If any of the three lists prints something, **stop**. This runbook did not
create it. Report it, and do not continue.

```powershell
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$agentCred = az ad app credential reset --id $agentId --create-cert --end-date $end --append --display-name fns-m3-probe | ConvertFrom-Json

$certs = @(az ad app credential list --id $agentId --cert | ConvertFrom-Json)
$limit = (Get-Date).ToUniversalTime().AddHours(24)
if ($certs.Count -ne 1 -or ([datetime]$certs[0].endDateTime).ToUniversalTime() -gt $limit) {
    Write-Error "STOP: expected exactly one certificate valid for at most 1 day. Go to Emergency cleanup."
} else {
    "OK: one certificate ($($certs[0].displayName)), ends $($certs[0].endDateTime)"
}
Start-Sleep -Seconds 180                         # new certificates take ~3 minutes (FINDINGS)
```

Continue only after `OK`.

## 6. Run the probes as `sp-billing-agent`

The agent signs in under its own temporary CLI profile. Your login is not in that
profile, so nothing in this window can use it by accident. The `fns` verifier
gets yet another, empty profile (V1).

```powershell
$agentDir = Join-Path $env:TEMP "fns-agent-az"
New-Item -ItemType Directory -Force $agentDir | Out-Null
$env:AZURE_CONFIG_DIR = $agentDir
az login --service-principal --username $agentId --certificate $agentCred.fileWithCertAndPrivateKey --tenant $tenant --allow-no-subscriptions
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table   # type: servicePrincipal, user: $agentId

uv run fns prove --contract contracts\lab\billing-agent.fns.yaml --snapshot $snap --live --scope scope.lab.yaml --record fixtures/lab-run-3 --identity local-verifier
$LASTEXITCODE                                    # expected: 1
```

If the login fails with `AADSTS700027`, wait 3 more minutes and repeat only the
`az login --service-principal` line. Then go straight to step 7. Run nothing
else as the agent.

**Expected output.**

- The first line is `LIVE probes as object <agent object id> (appid <$agentId>)`.
- The findings match the table below.
- The summary reads `passed: 1  critical reachable: 11  still-do failed: 0
  inconclusive: 1`.
- Then `signer: offline-test`, `TEST SIGNATURE: …` and `contract FAILED (exit 1)`.
- `recorded fixtures/lab-run-3/probes.json`, with **no** `not recorded` lines.
- `run directory .fns/runs/<run id>`.

| Item | Probes (as the agent) | Verdict | Coverage |
| --- | --- | --- | --- |
| KV `secrets/get` | pre-flight sees the tag; `GET` returns `403` `Forbidden`/`ForbiddenByRbac`; `vaults/write` listed | `fail` | evaluated-only |
| KV `secrets/list` | `GET /secrets` returns `403` `Forbidden`/`ForbiddenByRbac`; `vaults/write` listed | `fail` | evaluated-only |
| payroll `blob/read` | `HEAD` returns `403` `AuthorizationPermissionMismatch`; `listKeys` listed | `fail` | evaluated-only |
| payroll and invoices `listKeys` | `listKeys/action` listed | `fail` | evaluated-only |
| `directory:tenant` (2), both applications (4) | no probe (E2) | `fail` | modeled-only |
| invoices `blob/read` (must still do) | `HEAD` returns `200` | **`pass`** | **verified (observed)** |
| invoices `blob/write` (must still do) | data action listed, no write probe (E4) | `inconclusive` | evaluated-only |

Exit codes:

- **4:** the wrong identity is signed in, and nothing was sent. The message
  names the object ID, or says the `appid` does not match.
- **2:** the scope expired or is invalid. Renew it (step 2) **after** step 7.

In both cases go to step 7 now. Do not retry as another identity.

## 7. Sign the agent out and delete its certificate (immediately)

```powershell
az logout
Remove-Item Env:AZURE_CONFIG_DIR
foreach ($i in 1..5) {   # Windows can hold the profile briefly; in M3 it went 10 s later
    Remove-Item -Recurse -Force $agentDir -ErrorAction SilentlyContinue
    if (-not (Test-Path $agentDir)) { break }
    Start-Sleep -Seconds 3
}
Test-Path $agentDir                                                    # must print False
az account show --query "user.name" -o tsv                        # you again, not the agent

# step 5 checked the list was empty first, so every certificate here is this run's
foreach ($k in @(az ad app credential list --id $agentId --cert --query "[].keyId" -o tsv)) {
    az ad app credential delete --id $agentId --key-id $k --cert
}
Remove-Item $agentCred.fileWithCertAndPrivateKey
```

**Verify. Every line must print nothing, or `False`:**

```powershell
az ad app credential list --id $agentId --cert -o tsv
az ad app credential list --id $agentId -o tsv
az ad sp credential list --id $agentId --cert -o tsv
Test-Path $agentCred.fileWithCertAndPrivateKey
Test-Path $agentDir
```

If a list still shows a certificate, run the `foreach` again and repeat the
checks.

Access tokens the agent already received stay valid until they expire, which is
at most about 90 minutes. Deleting the certificate stops it getting new ones.

## 8. Check the journal and the recording

The journal of the run, as the gate saw it. Every row must be `allowed`:

```powershell
$run = (Get-ChildItem .fns\runs -Directory | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
uv run python -I -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); [print(*r) for r in c.execute('select decision, operation, count(*) from gate_decisions group by 1,2 order by 1,2')]" "$run\journal.sqlite"
```

Expected, 14 decisions:

```
allowed arm:Microsoft.Authorization/permissions/read 9
allowed arm:Microsoft.KeyVault/vaults/secrets/read 1
allowed blob:HEAD /invoices/invoice-0001-SYNTHETIC.json 1
allowed blob:HEAD /payroll/employees-SYNTHETIC.csv 1
allowed kv:GET /secrets 1
allowed kv:GET /secrets/payroll-db-password 1
```

The recording:

```powershell
uv run pytest tests/fixtures/test_no_real_ids.py -q
git status --short fixtures/lab-run-3          # _idmap.json must NOT be listed
Get-Content fixtures\lab-run-3\probes.json     # "Recorded from the lab by fns prove --live on <date>"; 13 results
Copy-Item contracts\lab\billing-agent.fns.yaml fixtures\lab-run-3\contract.fns.yaml
uv run fns demo prove --fixture fixtures/lab-run-3
$LASTEXITCODE                                    # expected: 1, same verdicts as step 6, every line FIXTURE
```

Do not commit `lab-run-3` yourself. It goes in its own PR, after the checks
above.

Finally:

```powershell
az logout
```

## 9. Report back

Send:

- **Step 2:** the plan summary line, the `fns scope check` output (you can
  redact the GUIDs), and the `tags` from the ARM read.
- **Step 3:** the scout digest and the Collectors table.
- **Step 5:** the `OK: one certificate …` line.
- **Step 6:**
  - the exit code and the summary line;
  - the Findings block;
  - any `not recorded` line;
  - for any probe that came back `unknown`, its detail line.
- **Step 7:** confirmation that all five checks printed nothing or `False`.
- **Step 8:** the journal rows, the `test_no_real_ids` result, and the replay's
  exit code.
- Anything that differed from the tables above. Every error code that differs
  from the documented one is a FINDINGS entry.

After that:

- the lab-run-3 PR: the recording, the M3 regression test, `fns demo prove`
  defaulting to lab-run-3, and the README "Real vs. fixture" row;
- signing on Sigstore production, which needs your explicit approval (V3);
- the `m3` tag.

## Emergency cleanup (if the session dies midway)

Use this if the terminal closed, the machine slept or rebooted, or anything
failed after step 3 or step 5 created a certificate. It is safe to run even if
nothing was created.

1. **Open a new PowerShell window** at the repository root. The old window's
   variables are gone. A new window does not have the agent's or the scout's
   `AZURE_CONFIG_DIR`, so `az` uses your own default profile.

2. **Remove the temporary CLI profiles.** They hold the agent's and the scout's
   logins.

   ```powershell
   Remove-Item Env:AZURE_CONFIG_DIR -ErrorAction SilentlyContinue
   foreach ($d in @("fns-agent-az", "fns-scout-az")) {
       $p = Join-Path $env:TEMP $d
       foreach ($i in 1..5) {   # Windows can hold a profile briefly; retry
           Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue
           if (-not (Test-Path $p)) { break }
           Start-Sleep -Seconds 3
       }
       if (Test-Path $p) { Write-Warning "still there: $p (close other az windows, rerun)" }
   }
   az account list --query "[?user.type=='servicePrincipal'].user.name" -o tsv   # must print nothing
   ```

   If that last line prints an ID, a service principal is signed in to your
   default profile. Run `az account clear`, which signs out every account.

3. **Sign in as yourself:**

   ```powershell
   az login --tenant <TENANT_ID>
   ```

4. **Delete every certificate on both lab identities.** The lab creates no
   credentials (`tests/test_lab.py`), so anything listed here came from a
   runbook.

   ```powershell
   $agentId = az ad app list --display-name sp-billing-agent --query "[0].appId" -o tsv
   $scoutId = az ad app list --display-name sp-fns-scout --query "[0].appId" -o tsv
   foreach ($id in @($agentId, $scoutId)) {
       az ad app credential list --id $id --cert --query "[].{keyId:keyId, name:displayName, end:endDateTime}" -o table
       foreach ($k in @(az ad app credential list --id $id --cert --query "[].keyId" -o tsv)) {
           az ad app credential delete --id $id --key-id $k --cert
       }
   }
   ```

5. **Look for client secrets and service-principal credentials.** No runbook
   creates these.

   ```powershell
   foreach ($id in @($agentId, $scoutId)) {
       az ad app credential list --id $id -o table
       az ad sp credential list --id $id --cert -o table
   }
   ```

   If anything is listed, report it before you delete it. It would mean
   something other than this runbook made a credential.

6. **Delete the PEM files.** `az ad app credential reset --create-cert` writes
   the certificate and private key to a `tmp*.pem` file, normally in your home
   folder. If the old window's output is still visible, it named the file in
   `fileWithCertAndPrivateKey`. To find recent ones:

   ```powershell
   $pems = @(foreach ($dir in @($HOME, $env:TEMP)) {
       Get-ChildItem $dir -Filter "tmp*.pem" -File -ErrorAction SilentlyContinue |
           Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-2) } |
           Where-Object { Select-String -Path $_.FullName -Pattern "PRIVATE KEY" -Quiet }
   })
   $pems | Select-Object FullName, LastWriteTime
   ```

   Check that the list holds only files from this run (by their times), then:

   ```powershell
   $pems | Remove-Item
   ```

7. **Verify.** Every line must print nothing:

   ```powershell
   foreach ($id in @($agentId, $scoutId)) {
       az ad app credential list --id $id --cert -o tsv
       az ad app credential list --id $id -o tsv
       az ad sp credential list --id $id --cert -o tsv
   }
   az account list --query "[?user.type=='servicePrincipal'].user.name" -o tsv
   ```

8. **Clean up the partial recording.** `fixtures/lab-run-3` is untracked, and its
   `_idmap.json` holds real IDs. If the run did not finish, delete the folder
   and start again from step 3 later:

   ```powershell
   git status --short fixtures/lab-run-3
   Remove-Item -Recurse -Force fixtures\lab-run-3
   ```

   `.fns/` is gitignored. Partial runs there can stay or be deleted.

9. **Report** what happened, which step it stopped at, and the output of the
   step 7 checks.

## Troubleshooting

- **`AADSTS700027` on a service-principal sign-in:** the new certificate has not
  propagated yet (FINDINGS, 2026-11-26). Wait 3 more minutes and repeat only the
  `az login --service-principal` line.
- **Exit 4, `not a test identity` or `appid does not match`:** the wrong account
  is current. In the agent's profile, `az account show` must show `$agentId`. Go
  to step 7 and do not retry as anyone else.
- **Exit 4, `principal-mismatch` or `PrincipalMismatchError`:** a later token
  belonged to a different object than the first one. Stop, go to step 7, and
  report it.
- **`secrets/get` not run, "not tagged fns-data=synthetic":** the pre-flight
  did not see the tag, so no Key Vault `GET` was sent for the secret, by design
  (V6). Check the ARM read in step 2. If Terraform shows the tag but ARM does
  not, that is a FINDINGS entry. The item fails anyway on the unhardened lab.
- **A data read is `unknown` with `401`:** the token audience is wrong or the
  token is missing. Report the error code. Do not retry with another identity.
- **`ForbiddenByFirewall` or `AuthorizationFailure`:** a network rule is in the
  way. The lab sets none, so report it. The probe stays `unknown` by design
  (V5).
- **Invoices `HEAD` returns `403`:** Storage Blob Data Contributor did not reach
  the data plane, or it was removed. That is a `must_still_do` failure. Report
  it, and do not change RBAC.
- **`not recorded (cannot be replayed)` lines:** those probes were `unknown`.
  The recording leaves them out, so the replay in step 8 will differ from step
  6. Report the lines.
- **`az ad app credential reset` rejects `--end-date` or `--display-name`:**
  nothing was created. Drop `--display-name`, or use a date-only end date of
  tomorrow, which is midnight UTC and so less than 24 hours away:
  `$end = (Get-Date).ToUniversalTime().AddDays(1).ToString("yyyy-MM-dd")`. The
  `OK` check in step 5 still enforces the 1-day limit.
- **The plan in step 2 shows other changes:** type `no`. Something drifted since
  M2; send the plan output.
