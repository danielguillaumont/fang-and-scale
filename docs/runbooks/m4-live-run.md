# M4 live run: record, strike, harden, prove the fix

> **Not run yet.** Written 2026-11-27 from `docs/milestones/M4-plan.md`
> (sessions A to D) and `docs/milestones/M4-strikes-plan.md`. Every `fns`
> command and every output shown here has been run against the recorded
> fixtures only. Where the live output may differ, the text says so.

> **Commands that prompt** (`lab-up`, `lab-down`, `terraform -chdir=lab apply`)
> are each in a block of their own. Paste them **alone**: Terraform reads the
> next pasted line as the answer to its `yes` prompt (FINDINGS).

All commands are Windows PowerShell, run from the repository root, **by you**. I
make no Azure call and hold no lab credential. Nothing here is filled in with a
real value. Every ID comes from `terraform output` or from `az` at run time,
apart from the tenant and subscription you type in step A1.

> Use the **dedicated lab tenant**, as in M1 to M3.

## What this run does

| Session | What | Creates | Removed in |
| --- | --- | --- | --- |
| A | Rebuild the lab, baseline scout recorded as `fixtures/lab-run-4` | everything in `lab/`, with a new random suffix; a 1-day scout certificate | A4 (certificate); Teardown (lab) |
| B | Monitoring on (workspace, Sentinel, diagnostic settings, the 11 rules); legitimate use as the agent; `fns record` | 18 resources; a 1-day agent certificate | B2 (certificate); Teardown |
| C | `fns strike` S1 to S3, then one KQL query per strike (D5) | 1 resource (the strike expiry); 1-day scout and agent certificates; each strike's writes, all undone by the tool | C5 (certificates); C4 (strike writes) |
| D | Harden, apply, prove the fix, D-1 to D-5 (D6), recorded as `fixtures/lab-run-5` | 1-day certificates; nothing else, unless a D-step succeeds (undone at once) | D8 |
| Teardown | `lab-down`, then the checks | | |

- **Time:** A 1.5 h, B 1 h plus up to a day for logs, C 2 h (mostly waiting
  for alerts), D 1.5 h.
- **Cost:** under $5 if C and D fall inside the 31-day Sentinel trial that B
  starts (`docs/milestones/M4-plan.md`, "Trials, cost and expiry").
- **Writes the tool makes:** only `fns strike run` in C4 and D6. Each write is
  in a plan you approve by its hash, goes only to a lab object, and is undone
  and verified before the command exits.
- **Not in this run:** S4 (the escalated sign-in and the marker role). It waits
  for its own decision (`docs/DECISIONS.md`, "Proposal, pending review: S4").
  `harden --apply` is not built: you apply the diff yourself.

> [!CAUTION]
> **`sp-billing-agent` is the escalation-capable identity.** Until harden it
> holds Contributor on `rg-fns-lab` and `Application.ReadWrite.OwnedBy`, and it
> owns `app-escalation-target`.
> - Its credential is always a certificate valid for **at most 1 day**, created
>   right before it is needed and deleted right after. Never a client secret.
> - Check its credential lists are **empty** before you create one, and again
>   after you delete it.
> - While a window is signed in as the agent, run **only** the commands in that
>   step.
> - Do not copy, move or open a PEM file. The step that made it deletes it.
> - **If anything goes wrong, or a session dies, go to
>   [Emergency cleanup](#emergency-cleanup) now.**

**Stop rules** (clean up first, then report back):

- A Terraform plan differs from the one this runbook expects.
- `fns strike run` exits 4 or 5, or prints a `verify FAIL` line.
- A D-step in D6 shows `unexpected-success`.
- `harden` proposes anything other than the two grants in D2.

---

## Start of every session

Each session can run in a new PowerShell window, on another day. Start each one
with these lines, as **yourself**:

```powershell
az login --tenant <TENANT_ID>
az account set --subscription <SUBSCRIPTION_ID>
az account show --query "{tenant:tenantId, sub:id, user:user.name}" -o table
$tenant = az account show --query tenantId -o tsv
$scoutDir = Join-Path $env:TEMP "fns-m4-scout-az"
$agentDir = Join-Path $env:TEMP "fns-m4-agent-az"
```

Check that the table shows the lab tenant, the lab subscription and your own
lab account. You need **Global Administrator** (for the Entra diagnostic setting
in B1) and **Owner** on the subscription.

Once the lab exists (from A2 on), also run:

```powershell
$scoutId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
$agent = terraform -chdir=lab output -json billing_agent | ConvertFrom-Json
$agentId = $agent.client_id
$agentOid = $agent.object_id
$mon = terraform -chdir=lab output -json monitoring | ConvertFrom-Json   # null before B1
$ws = $mon.workspace_customer_id
```

## Session A: rebuild the lab

### A1. Update your checkout

Run [Start of every session](#start-of-every-session) first (its first block
only: the lab doesn't exist yet).

```powershell
git switch main
git pull
uv run poe setup
```

### A2. Rebuild the lab (you approve the apply)

`lab/terraform.tfvars` holds IDs only. Keep `enable_monitoring` and
`enable_strikes` **unset** (both default to `false`) for this session.

```powershell
Get-Content lab\terraform.tfvars                 # tenant, subscription, location, prefix
uv run poe lab-check                             # fmt + validate, no credentials used
```

Then paste this line **on its own**, and type the answer yourself:

```powershell
uv run poe lab-up
```

**Review the plan before typing `yes`:**

- **37 to add, 0 to change, 0 to destroy** with the defaults;
- **39 to add** if you set `budget_alert_email`;
- **one more** if `github_repository` is set.

Anything else is a stop: answer `no`, and send the plan summary.

```powershell
uv run fns scope check scope.lab.yaml
terraform -chdir=lab output -json resources | ConvertFrom-Json   # the new names
```

`scope check`: the lab tenant, subscription and `rg-fns-lab`, 17 scout and 6
prove operations, no `strike` operations, and an expiry 7 days out. Wait about 10
minutes for the Graph grants to show up in tokens.

### A3. Baseline scout as `sp-fns-scout`, recorded as `lab-run-4`

Run the second block of [Start of every session](#start-of-every-session) now
that the lab exists.

```powershell
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
az ad app credential list --id $scoutId -o tsv                   # no client secrets either
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$scoutCred = az ad app credential reset --id $scoutId --create-cert --end-date $end --append --display-name fns-m4-scout | ConvertFrom-Json
Start-Sleep -Seconds 180                         # new certificates take ~3 minutes (FINDINGS)

New-Item -ItemType Directory -Force $scoutDir | Out-Null
$env:AZURE_CONFIG_DIR = $scoutDir
az login --service-principal --username $scoutId --certificate $scoutCred.fileWithCertAndPrivateKey --tenant $tenant -o none
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table   # type: servicePrincipal

uv run fns scout --scope scope.lab.yaml --record fixtures/lab-run-4
$snap = (Get-ChildItem .fns\snapshots\*.LIVE.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

If the login fails with `AADSTS700027`, wait 3 more minutes and repeat only the
`az login --service-principal` line.

Expected: 12 collectors. Eleven are `complete`, and `pim.eligibility` is
`not-applicable`. The lab group `grp-fns-billing` (D3) now gives
`sp-billing-agent` one `memberOf` entry.

### A4. Remove the scout certificate

```powershell
az logout
Remove-Item Env:AZURE_CONFIG_DIR
foreach ($i in 1..5) {   # Windows can hold the profile briefly
    Remove-Item -Recurse -Force $scoutDir -ErrorAction SilentlyContinue
    if (-not (Test-Path $scoutDir)) { break }
    Start-Sleep -Seconds 3
}
Test-Path $scoutDir                                              # must print False
az account show --query "user.name" -o tsv                       # you again, not the scout
# A3 checked the list was empty first, so every certificate here is this run's
foreach ($k in @(az ad app credential list --id $scoutId --cert --query "[].keyId" -o tsv)) {
    az ad app credential delete --id $scoutId --key-id $k --cert
}
Remove-Item $scoutCred.fileWithCertAndPrivateKey
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
uv run pytest tests/fixtures/test_no_real_ids.py -q
git status --short fixtures/lab-run-4                            # _idmap.json must NOT be listed
```

The `Directory.Read.All` and custom-role tests from the M4 plan ("Session A,
continued") are not part of this runbook. They change the scout, not the agent,
and get their own steps when the custom role is built.

---

## Session B: monitoring, legitimate use, record

### B1. Turn monitoring on (workspace, diagnostic settings, rules)

Add this line to `lab/terraform.tfvars`:

```
enable_monitoring = true
```

```powershell
uv run fns detections check                      # every rule against its sample rows
uv run fns detections export --terraform --check # lab/detections.json is up to date
```

Then paste this line **on its own**:

```powershell
uv run poe lab-up
```

**The plan must be 18 to add, 0 to change, 0 to destroy**: the workspace, the
Sentinel onboarding, five diagnostic settings (Activity Log, Key Vault, two blob
services, Entra) and 11 scheduled rules. Anything else is a stop.

```powershell
$mon = terraform -chdir=lab output -json monitoring | ConvertFrom-Json
$ws = $mon.workspace_customer_id
$mon.rules.Count                                 # must print 11
az rest --method get --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" --query "value[].{name:name, logs:properties.logs[?enabled].category}" -o json
```

The Entra list shows one setting, ending in `-entra`, with `AuditLogs` and
`ServicePrincipalSignInLogs`. Then open the workspace in the **Defender portal**
(Microsoft Sentinel) and check that the free trial shows 31 days. Sessions C and D
must fit inside it.

### B2. Legitimate use as the agent (by hand)

This is the agent's normal work, which record mode turns into `must_still_do`
items (PLAN §5). The upload is a write, and you make it, not the tool.

```powershell
az ad app credential list --id $agentId --cert -o tsv            # must print nothing
az ad app credential list --id $agentId -o tsv                   # no client secrets either
az ad sp credential list --id $agentId --cert -o tsv             # nothing on the service principal
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$agentCred = az ad app credential reset --id $agentId --create-cert --end-date $end --append --display-name fns-m4-agent | ConvertFrom-Json
Start-Sleep -Seconds 180
$invoices = ((terraform -chdir=lab output -json resources | ConvertFrom-Json).storage_invoices -split "/")[-1]
$useAt = (Get-Date).ToUniversalTime()
```

```powershell
New-Item -ItemType Directory -Force $agentDir | Out-Null
$env:AZURE_CONFIG_DIR = $agentDir
az login --service-principal --username $agentId --certificate $agentCred.fileWithCertAndPrivateKey --tenant $tenant --allow-no-subscriptions -o none
az account show --query "{tenant:tenantId, type:user.type}" -o table   # type: servicePrincipal
az storage blob download --auth-mode login --account-name $invoices -c invoices -n invoice-0001-SYNTHETIC.json -f (Join-Path $env:TEMP "fns-m4-invoice.json") -o none
az storage blob upload --auth-mode login --account-name $invoices -c invoices -n invoice-m4-SYNTHETIC.json -f (Join-Path $env:TEMP "fns-m4-invoice.json") --overwrite -o none
az logout
Remove-Item Env:AZURE_CONFIG_DIR
```

Then delete the certificate right away:

```powershell
foreach ($i in 1..5) {
    Remove-Item -Recurse -Force $agentDir -ErrorAction SilentlyContinue
    if (-not (Test-Path $agentDir)) { break }
    Start-Sleep -Seconds 3
}
foreach ($k in @(az ad app credential list --id $agentId --cert --query "[].keyId" -o tsv)) {
    az ad app credential delete --id $agentId --key-id $k --cert
}
Remove-Item $agentCred.fileWithCertAndPrivateKey
Remove-Item (Join-Path $env:TEMP "fns-m4-invoice.json")
az ad app credential list --id $agentId --cert -o tsv            # must print nothing
Test-Path $agentDir                                              # must print False
```

### B3. Export the agent's rows

Wait for the rows: Activity Log within minutes, blob logs within about 15
minutes. These files hold **real IDs**: they stay in `.fns\` (gitignored).
Don't paste them anywhere. `fns record` reads them on your machine.

```powershell
az extension add --name log-analytics --upgrade -o none
$logs = New-Item -ItemType Directory -Force .fns\m4\logs
$since = $useAt.ToString("yyyy-MM-ddTHH:mm:ssZ")
$qBlob = "StorageBlobLogs | where TimeGenerated > datetime($since) | where RequesterObjectId =~ '$agentOid'"
$qActivity = "AzureActivity | where TimeGenerated > datetime($since) | where Caller in~ ('$agentOid', '$agentId')"
[IO.File]::WriteAllText((Join-Path $logs "blob.json"), (az monitor log-analytics query -w $ws --analytics-query $qBlob -o json | Out-String))
[IO.File]::WriteAllText((Join-Path $logs "activity.json"), (az monitor log-analytics query -w $ws --analytics-query $qActivity -o json | Out-String))
(Get-Content (Join-Path $logs "blob.json") | ConvertFrom-Json).Count   # at least 2
```

If the blob count is 0, wait 15 minutes and run the last three lines again.

### B4. Record

```powershell
uv run fns record (Join-Path $logs "blob.json") (Join-Path $logs "activity.json") --identity $agentOid --contract contracts\lab\billing-agent.fns.yaml --out .fns\m4\recorded.fns.yaml
```

Expected: `resource: st-invoices` with `blob/read` and `blob/write`,
`source: recorded`, and an `unmapped` list. Send the output and the `unmapped`
list (they name operations, not IDs).

---

## Session C: strikes S1 to S3 and detection results

### C1. Turn strikes on

Add this line to `lab/terraform.tfvars`:

```
enable_strikes = true
```

Then paste this line **on its own**:

```powershell
uv run poe lab-up
```

**The plan:** `time_offset.strike_expiry[0]` is created, and `local_file.scope` is
replaced, because its content gains the `strike:` block. That is **2 to add, 0
to change, 1 to destroy**. Anything else is a stop.

```powershell
uv run fns scope check scope.lab.yaml
terraform -chdir=lab output -raw scope_expires_at
```

`scope check` now also lists 7 `strike` operations and a strike expiry 4 hours
out (`strike_valid_hours`). Sessions C and D must each start inside that
window. D5 renews it.

### C2. A certificate for the scout and one for the agent, each in its own profile

The strike signs in **two** identities: the agent writes, and the read-only
scout reads the state before and after (decision of 2026-11-27, two CLI
profiles). Neither profile is used in this window afterwards: `fns` reads each
one for its own token.

```powershell
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
az ad app credential list --id $agentId --cert -o tsv            # must print nothing
az ad app credential list --id $agentId -o tsv                   # must print nothing
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$scoutCred = az ad app credential reset --id $scoutId --create-cert --end-date $end --append --display-name fns-m4-scout | ConvertFrom-Json
$agentCred = az ad app credential reset --id $agentId --create-cert --end-date $end --append --display-name fns-m4-agent | ConvertFrom-Json
Start-Sleep -Seconds 180

New-Item -ItemType Directory -Force $scoutDir, $agentDir | Out-Null
$env:AZURE_CONFIG_DIR = $scoutDir
az login --service-principal --username $scoutId --certificate $scoutCred.fileWithCertAndPrivateKey --tenant $tenant -o none
$env:AZURE_CONFIG_DIR = $agentDir
az login --service-principal --username $agentId --certificate $agentCred.fileWithCertAndPrivateKey --tenant $tenant --allow-no-subscriptions -o none
Remove-Item Env:AZURE_CONFIG_DIR
az account show --query "user.name" -o tsv                       # you, in this window
```

### C3. Plan the strikes (reads only)

```powershell
uv run fns strike plan --strikes S1,S2,S3 --scope scope.lab.yaml --scout-config $scoutDir
$plan = (Get-ChildItem .fns\strike\*\plan.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
(Get-Content $plan | ConvertFrom-Json).writes | ForEach-Object { "{0}  {1} {2}" -f $_.key, $_.request.method, $_.request.url; ($_.request.body | ConvertTo-Json -Compress -Depth 6); "  undo: " + (($_.undo | ForEach-Object { "{0} {1}" -f $_.method, $_.url }) -join "; ") }
```

The table the command prints shortens the URLs, so the last line prints each
write in full. **Review every line.** Expected: three writes, all `allowed`:

| Write | Request | Undo |
| --- | --- | --- |
| `S1/list-keys` | `POST .../storageAccounts/stpayroll<suffix>/listKeys` | `regenerateKey` key1, then key2 (SD1) |
| `S2/vault-tag` | `PATCH .../vaults/kv-crown-<suffix>`, body `tags` only, with `fns-strike` added | `PATCH` the pre-state tags back |
| `S3/add-password` | `POST /applications/<app-escalation-target>/addPassword`, `fns-strike-<run>`, ending within 1 hour | `removePassword` of that `keyId` |

Any other target, method or body key is a stop. The plan expires 1 hour after it
was made. If you need longer, plan again.

**Approve:** copy the 64 hex characters after `plan sha256:` from the output.
Typing them is the approval.

```powershell
$hash = "<the 64 hex characters after plan sha256:>"
```

### C4. Run the strikes (the only writes in session C)

```powershell
$strikeAt = (Get-Date).ToUniversalTime()
uv run fns strike run --plan $plan --approve $hash --scope scope.lab.yaml --agent-config $agentDir --scout-config $scoutDir
$LASTEXITCODE                                    # expected: 0
$cRun = Split-Path $plan
```

**Expected** (the fixture run, `fns strike run --fixture fixtures/strike-demo`,
prints the same shape):

```
strike run <run id> (plan sha256:<hash>)
| write           | expect  | outcome   | status | undo     |
| S1/list-keys    | allowed | succeeded | 200    | 200, 200 |
| S2/vault-tag    | allowed | succeeded | 200    | 200      |
| S3/add-password | allowed | succeeded | 200    | 204      |
verify ok   credentials <app>: as before
verify ok   tags <vault>: as before
verify ok   keys <payroll account>: both regenerated
exit 0: clean: every write undone and verified
```

The keys from `listKeys` and the password from `addPassword` are never printed,
journaled or written to disk: the transport strips them first.

- **Exit 4:** the scope gate or the plan check refused. Everything before it was
  undone. Send the message.
- **Exit 5, or any `verify FAIL`:** go to [Emergency cleanup](#emergency-cleanup)
  now.
- A `403` where `allowed` was expected is a FINDINGS entry (the permission the
  strike plan assumed is not the one Azure checks).

### C5. Sign both identities out and delete their certificates (immediately)

```powershell
foreach ($d in $agentDir, $scoutDir) {
    $env:AZURE_CONFIG_DIR = $d
    az logout
}
Remove-Item Env:AZURE_CONFIG_DIR
foreach ($i in 1..5) {
    Remove-Item -Recurse -Force $agentDir, $scoutDir -ErrorAction SilentlyContinue
    if (-not ((Test-Path $agentDir) -or (Test-Path $scoutDir))) { break }
    Start-Sleep -Seconds 3
}
foreach ($k in @(az ad app credential list --id $agentId --cert --query "[].keyId" -o tsv)) {
    az ad app credential delete --id $agentId --key-id $k --cert
}
foreach ($k in @(az ad app credential list --id $scoutId --cert --query "[].keyId" -o tsv)) {
    az ad app credential delete --id $scoutId --key-id $k --cert
}
Remove-Item $agentCred.fileWithCertAndPrivateKey, $scoutCred.fileWithCertAndPrivateKey
```

**Verify. Every line must print nothing, or `False`:**

```powershell
az ad app credential list --id $agentId --cert -o tsv
az ad app credential list --id $agentId -o tsv
az ad app credential list --id $scoutId --cert -o tsv
Test-Path $agentDir
Test-Path $scoutDir
Test-Path $agentCred.fileWithCertAndPrivateKey
```

### C6. Detection results: one query per strike (D5)

The queries return no IDs, IP addresses or user names, so their output is safe to
paste. The identities are used only in `where`, never in the output.

```powershell
$since = $strikeAt.AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ssZ")

$qS1 = "AzureActivity | where TimeGenerated > datetime($since) | where Caller in~ ('$agentOid', '$agentId') | where OperationNameValue in~ ('MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION', 'MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION') | project TimeGenerated, OperationNameValue, ActivityStatusValue"

$qS2 = "AzureActivity | where TimeGenerated > datetime($since) | where Caller in~ ('$agentOid', '$agentId') | where OperationNameValue =~ 'MICROSOFT.KEYVAULT/VAULTS/WRITE' | project TimeGenerated, OperationNameValue, ActivityStatusValue"

$qS3 = "AuditLogs | where TimeGenerated > datetime($since) | where OperationName contains 'Certificates and secrets management' | mv-expand Target = TargetResources | where tostring(Target.displayName) == 'app-escalation-target' | mv-apply P = Target.modifiedProperties on (summarize Before = sumif(array_length(todynamic(tostring(P.oldValue))), tostring(P.displayName) == 'KeyDescription'), After = sumif(array_length(todynamic(tostring(P.newValue))), tostring(P.displayName) == 'KeyDescription')) | project TimeGenerated, OperationName, Result, Change = case(After > Before, 'add', After < Before, 'delete', 'unknown'), By = iff(isnotempty(tostring(InitiatedBy.app.servicePrincipalId)), 'app', 'user')"

$qAlerts = "SecurityAlert | where TimeGenerated > datetime($since) | where AlertName startswith 'fns: ' | summarize First = min(TimeGenerated), Alerts = count() by AlertName"
```

Poll every 10 minutes, for at most 2 hours after the strike:

```powershell
$deadline = $strikeAt.AddHours(2)
do {
    $alerts = @(az monitor log-analytics query -w $ws --analytics-query $qAlerts -o json | ConvertFrom-Json)
    "{0:u}  alerts: {1}" -f (Get-Date).ToUniversalTime(), (@($alerts | ForEach-Object { $_.AlertName }) -join "; ")
    if ($alerts.Count -ge 3) { break }
    Start-Sleep -Seconds 600
} while ((Get-Date).ToUniversalTime() -lt $deadline)

az monitor log-analytics query -w $ws --analytics-query $qS1 -o table
az monitor log-analytics query -w $ws --analytics-query $qS2 -o table
az monitor log-analytics query -w $ws --analytics-query $qS3 -o table
az monitor log-analytics query -w $ws --analytics-query $qAlerts -o table
"strike run started {0:u}" -f $strikeAt
```

**Expected:**

| Strike | Query | Rows | Rule that should fire (`AlertName`) |
| --- | --- | --- | --- |
| S1 | `qS1` | `LISTKEYS/ACTION` and two `REGENERATEKEY/ACTION`, `Success` | `storage-listkeys-by-workload`: "fns: Storage account keys listed by a monitored workload" |
| S2 | `qS2` | two `VAULTS/WRITE`, `Success` (the tag and its undo) | `keyvault-control-plane-write-by-workload`: "fns: Key Vault configuration changed by a monitored workload" |
| S3 | `qS3` | two rows, `By` = `app`: `Change` = `add`, then `delete` (the undo) | `app-credential-added-by-workload`: "fns: Credential added to an application or service principal by a workload identity" |

**Detection result per strike:** fired or not, and `First` minus the strike
time. A strike whose rows arrived but whose rule did not fire within 2 hours is
a `detection-gap` (PLAN §4). That is a result, not a stop.

- The `SecurityAlert` query has not run live yet. If it fails, or stays empty
  while the rows are there, open **Incidents** in the Defender portal and paste
  the alert names and times it shows.
- The rules run every 15 minutes over the last hour, so up to about 30 minutes on
  top of the log delay is normal.

---

## Session D: harden, apply, prove the fix, D-1 to D-5

### D1. Scout and contain

Sign the scout in again, in its own profile (A3 shows the full step):

```powershell
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$scoutCred = az ad app credential reset --id $scoutId --create-cert --end-date $end --append --display-name fns-m4-scout | ConvertFrom-Json
Start-Sleep -Seconds 180
New-Item -ItemType Directory -Force $scoutDir | Out-Null
$env:AZURE_CONFIG_DIR = $scoutDir
az login --service-principal --username $scoutId --certificate $scoutCred.fileWithCertAndPrivateKey --tenant $tenant -o none
uv run fns scout --scope scope.lab.yaml
Remove-Item Env:AZURE_CONFIG_DIR
$snap = (Get-ChildItem .fns\snapshots\*.LIVE.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
uv run fns contain --contract .fns\m4\recorded.fns.yaml --snapshot $snap
```

Expected: critical reachable as in lab-run-3 (11), give or take the lab group
from D3, which adds an edge but no role. Send the summary either way; only a
`must_still_do` failure is a stop here. The scout stays signed in, in its own
profile, for D6.

### D2. Propose the fix

```powershell
uv run fns harden --contract .fns\m4\recorded.fns.yaml --snapshot $snap --out harden.diff
Get-Content harden.diff
```

**Expected:** remove exactly two grants:

- `azurerm_role_assignment.billing_agent_rg_contributor` (Contributor on the RG);
- `azuread_app_role_assignment.billing_agent_owned_by` (Graph
  `Application.ReadWrite.OwnedBy`).

The model goes to 0 critical reachable, with `blob/read` and `blob/write` on
`st-invoices` still allowed. Anything else is a stop. Send the proposal and its
`plan sha256:` line.

### D3. Apply the diff (you, not the tool)

```powershell
git switch -c m4-harden
git apply harden.diff
git diff --stat
```

Then paste this line **on its own**:

```powershell
uv run poe lab-up
```

**The plan must be 0 to add, 0 to change, 2 to destroy**, and the two are the
grants in D2. Anything else is a stop: answer `no`.

### D4. A fresh scout: the model says 0

```powershell
$env:AZURE_CONFIG_DIR = $scoutDir
uv run fns scout --scope scope.lab.yaml
Remove-Item Env:AZURE_CONFIG_DIR
$snap = (Get-ChildItem .fns\snapshots\*.LIVE.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
uv run fns contain --contract .fns\m4\recorded.fns.yaml --snapshot $snap
```

Expected: **0 critical reachable**. Wait 10 minutes: removed grants can stay in
cached tokens for a while.

### D5. Renew the strike expiry

Only if the strike expiry printed by `scope check` is less than 1 hour away.
Paste this line **on its own**:

```powershell
terraform -chdir=lab apply "-replace=time_offset.strike_expiry[0]"
```

The plan: `time_offset.strike_expiry[0]` and `local_file.scope` replaced, **2
to add, 0 to change, 2 to destroy**.

### D6. D-1 to D-5: every attempt must be denied

```powershell
az ad app credential list --id $agentId --cert -o tsv            # must print nothing
az ad app credential list --id $agentId -o tsv                   # must print nothing
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$agentCred = az ad app credential reset --id $agentId --create-cert --end-date $end --append --display-name fns-m4-agent | ConvertFrom-Json
Start-Sleep -Seconds 180
New-Item -ItemType Directory -Force $agentDir | Out-Null
$env:AZURE_CONFIG_DIR = $agentDir
az login --service-principal --username $agentId --certificate $agentCred.fileWithCertAndPrivateKey --tenant $tenant --allow-no-subscriptions -o none
Remove-Item Env:AZURE_CONFIG_DIR

uv run fns strike plan --strikes D-1,D-2,D-3,D-4,D-5 --scope scope.lab.yaml --scout-config $scoutDir
$plan = (Get-ChildItem .fns\strike\*\plan.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
(Get-Content $plan | ConvertFrom-Json).writes | ForEach-Object { "{0}  {1} {2}" -f $_.key, $_.request.method, $_.request.url; ($_.request.body | ConvertTo-Json -Compress -Depth 6); "  undo: " + (($_.undo | ForEach-Object { "{0} {1}" -f $_.method, $_.url }) -join "; ") }
```

**Review.** Expected: five writes, all `expect denied`:

| Write | Request | Undo, only if it succeeds |
| --- | --- | --- |
| `D-1/add-password` | `addPassword` on `app-escalation-target` | `removePassword` |
| `D-2/add-password` | `addPassword` on `id-verifier` | `removePassword` |
| `D-3/add-password` | `addPassword` on `sp-fns-scout` | `removePassword` |
| `D-4/add-owner` | `owners/$ref` on `id-verifier`, the agent as owner | `DELETE .../owners/<agent>/$ref` |
| `D-5/add-owner` | `owners/$ref` on `sp-fns-scout`, the agent as owner | the same, on the scout app |

```powershell
$hash = "<the 64 hex characters after plan sha256:>"
uv run fns strike run --plan $plan --approve $hash --scope scope.lab.yaml --agent-config $agentDir --scout-config $scoutDir
$LASTEXITCODE                                    # expected: 0
$dRun = Split-Path $plan
```

**Expected:** every row `denied`, `403`, undo `-`; five `verify ok` lines; `exit
0: clean: every write undone and verified`.

- **Exit 1:** an attempt succeeded. It was undone at once, and the contract
  fails. This is a stop: finish D7 and D8 so the evidence is recorded, then
  report. It is a FINDINGS entry.
- **Exit 4 or 5:** as in C4.

### D7. Prove the fix as the agent, with the D-1 to D-5 evidence

```powershell
$env:AZURE_CONFIG_DIR = $agentDir
az account show --query "{tenant:tenantId, type:user.type}" -o table   # type: servicePrincipal
uv run fns prove --contract .fns\m4\recorded.fns.yaml --snapshot $snap --live --scope scope.lab.yaml --record fixtures/lab-run-5 --identity local-verifier --after-strike $dRun
$LASTEXITCODE
az logout
Remove-Item Env:AZURE_CONFIG_DIR
```

`--after-strike` adds each D-step's result to the finding it observes
(`docs/DECISIONS.md`, D6, approved 2026-11-27 with its guardrail). It refuses a
strike run from another tenant, another plan or another mode before anything is
recorded.

**Expected:**

| Item | Expected verdict | Why |
| --- | --- | --- |
| Key Vault `secrets/get`, `secrets/list`; payroll `blob/read` | **`pass`**, `verified` | observed denied, no path left |
| invoices `blob/read` (must still do) | **`pass`**, `verified` | observed allowed |
| `application:id-verifier`, `application:sp-fns-scout` (`credentials/update`, `owners/update`), `directory:tenant applications/credentials/update` | **`inconclusive`**, with the D-step's `denied` attached as context | the guardrail: a strike can add evidence or fail a finding, never pass one |
| `directory:tenant roleAssignments/write` | **`inconclusive`** | SD3: no direct attempt |

So expect **exit 3** (inconclusive over the contract's budget of 2), not 0.
Whether a strike denial may ever count toward `pass` is an open question
(`docs/STATUS.md`, "Needs Daniel"). Any finding that **fails** is a stop.

### D8. Sign out and delete the certificates

Run C5 again: it signs out both profiles and deletes both certificates. Then run
its verify block. Every line must print nothing, or `False`.

Check the recording:

```powershell
uv run pytest tests/fixtures/test_no_real_ids.py -q
git status --short fixtures/lab-run-5                            # _idmap.json must NOT be listed
```

Don't commit `lab-run-4` or `lab-run-5` yourself. Each goes in its own PR, after
my checks.

---

## Teardown

Once every fixture is committed. Paste this line **on its own**, check that it
destroys what A2, B1 and C1 added (less the two grants D3 removed), then type
`yes`:

```powershell
uv run poe lab-down
```

```powershell
az group exists -n rg-fns-lab                                    # must print false
foreach ($n in "sp-billing-agent", "app-escalation-target", "id-verifier", "sp-fns-scout") {
    "{0}: {1}" -f $n, (@(az ad app list --display-name $n --query "[].appId" -o tsv).Count)   # each must be 0
}
az rest --method get --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" --query "value[].name" -o tsv   # must list nothing ending in -entra
Remove-Item -Recurse -Force .fns\m4\logs
git switch main
```

Then set `enable_monitoring` and `enable_strikes` back to `false` (or remove the
lines) in `lab/terraform.tfvars`. The Sentinel trial ends with the workspace.

## Report back

Per session, paste:

- **A:** the plan summary line; the `scope check` output; the scout summary.
- **B:** the plan summary line; `$mon.rules.Count`; the `fns record` output.
- **C:** the plan summary line; the C3 review lines **with the IDs replaced by
  the lab names**; the full `fns strike run` output; `$LASTEXITCODE`; the C5
  checks; the four query outputs and the start time from C6.
- **D:** the harden proposal; the D3 plan summary; the D4 contain summary; the
  D6 run output; the D7 output and exit code; the D8 checks.
- **Teardown:** that every check printed what it should.

## Emergency cleanup

Run this if a session dies, `fns strike run` exits 5, a `verify FAIL` line
appears, or you are unsure. Sign in as **yourself** first
(`az login --tenant <TENANT_ID>`). Every command is safe to repeat.

### 1. Let the tool undo what its journal shows

`fns strike cleanup` runs, in reverse order, every undo the journal does not show
as done. It repeats an undo until it gets a 2xx. It needs both profiles signed
in (C2). If either certificate is already deleted, skip to step 2.

```powershell
$plan = (Get-ChildItem .fns\strike\*\plan.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
$journal = Join-Path (Split-Path $plan) "journal.sqlite"
uv run fns strike cleanup --plan $plan --approve $hash --journal $journal --scope scope.lab.yaml --agent-config $agentDir --scout-config $scoutDir
$LASTEXITCODE                                    # 0: clean and verified; go to step 3
```

To see what the journal holds (no bodies or secrets are in it):

```powershell
uv run python -I -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); [print(*r) for r in c.execute('select write_key, phase, at from strike_events order by id')]" $journal
```

A write whose last phase is `result` or `error`, with no `undo-result` after
it, still needs its undo.

### 2. Undo by hand, as yourself

Each block is safe to run even if that strike never ran.

```powershell
$res = terraform -chdir=lab output -json resources | ConvertFrom-Json
$agent = terraform -chdir=lab output -json billing_agent | ConvertFrom-Json
$apps = @{}
foreach ($n in "app-escalation-target", "id-verifier", "sp-fns-scout") { $apps[$n] = az ad app list --display-name $n --query "[0].appId" -o tsv }
```

**S3 and D-1 to D-3: strike passwords.** Delete every password named
`fns-strike-*` on the three apps:

```powershell
foreach ($n in $apps.Keys) {
    foreach ($k in @(az ad app credential list --id $apps[$n] --query "[?starts_with(displayName, 'fns-strike-')].keyId" -o tsv)) {
        az ad app credential delete --id $apps[$n] --key-id $k
    }
    "{0}: {1}" -f $n, (@(az ad app credential list --id $apps[$n] --query "[?starts_with(displayName, 'fns-strike-')]" -o tsv).Count)   # each must be 0
}
```

**D-4 and D-5: the agent as owner of `id-verifier` or `sp-fns-scout`.** Never
remove it from `app-escalation-target`: it owns that one by design (M2).

```powershell
foreach ($n in "id-verifier", "sp-fns-scout") {
    if (@(az ad app owner list --id $apps[$n] --query "[?id=='$($agent.object_id)']" -o tsv).Count -gt 0) {
        az ad app owner remove --id $apps[$n] --owner-object-id $agent.object_id
    }
    "{0}: {1}" -f $n, (@(az ad app owner list --id $apps[$n] --query "[?id=='$($agent.object_id)']" -o tsv).Count)   # each must be 0
}
```

**S2: the vault tag.** Remove only the `fns-strike` tag:

```powershell
$v = az keyvault show --ids $res.key_vault --query "tags.\"fns-strike\"" -o tsv
if ($v) { az tag update --resource-id $res.key_vault --operation Delete --tags "fns-strike=$v" -o none }
az keyvault show --ids $res.key_vault --query tags -o json       # project and purpose only
```

**S1: the payroll keys.** Make any key the strike read worthless:

```powershell
$payroll = ($res.storage_payroll -split "/")[-1]
az storage account keys renew -g rg-fns-lab -n $payroll --key primary -o none
az storage account keys renew -g rg-fns-lab -n $payroll --key secondary -o none
```

If the journal is lost, these blocks are also the search by name. They look for
every credential named `fns-strike-*`, any owner reference to the agent on the
two apps, and the vault tag `fns-strike`.

### 3. Delete the certificates and the profiles

```powershell
Remove-Item Env:AZURE_CONFIG_DIR -ErrorAction SilentlyContinue
foreach ($d in (Join-Path $env:TEMP "fns-m4-agent-az"), (Join-Path $env:TEMP "fns-m4-scout-az")) {
    Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
}
$agentId = (terraform -chdir=lab output -json billing_agent | ConvertFrom-Json).client_id
$scoutId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
foreach ($id in $agentId, $scoutId) {
    foreach ($k in @(az ad app credential list --id $id --cert --query "[?starts_with(displayName, 'fns-m4-')].keyId" -o tsv)) {
        az ad app credential delete --id $id --key-id $k --cert
    }
    az ad app credential list --id $id --cert -o tsv             # must print nothing
}
```

The PEM files are in your user profile, under the names `az ad app credential
reset` printed. Delete them if the session died before C5 or D8.

### 4. If nothing else works

Last, on its own line (it prompts). The strikes write only to lab objects, so
destroying the lab removes everything a strike can touch:

```powershell
uv run poe lab-down
```

- **A certificate:** if nobody deletes it, it stops working within 24 hours, and
  `lab-down` deletes the application anyway.
- **A strike password:** it ends 1 hour after it was made (the gate refuses a
  longer one).
- **The Entra diagnostic setting:** it is tenant-level. Check, as in Teardown,
  that it is gone.
