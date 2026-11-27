# M4 step 1: the log path check

Decision D1 (`docs/milestones/M4-plan.md`, "Step 1"). The question: on this tenant,
which has **no Entra P1 or P2 licence**, can a diagnostic setting send
**`AuditLogs`** and **`ServicePrincipalSignInLogs`** to a Log Analytics workspace?
Microsoft's current page lists no licence prerequisite, but older guidance says
sign-in export needs P1 or P2. This run settles it before any strike code is
written or any trial is started.

All commands are Windows PowerShell, run from the repository root, **by you**. I
make no Azure call. Nothing here is filled in with a real value. Every ID comes
from `terraform output` or from `az` at run time, apart from the tenant and
subscription you type in step 1.

> Use the **dedicated lab tenant**, as in M1 to M3.

## What this run does

| Step | Creates | Removed in |
| --- | --- | --- |
| 2. Rebuild the lab | everything in `lab/`, with a **new random suffix** | step 10 (`lab-down`) |
| 3. Workspace | `rg-fns-logcheck` and `law-fns-logcheck` (Log Analytics) | step 9 |
| 4. Diagnostic setting | the tenant-level Entra setting `fns-logcheck`. `lab-down` does **not** remove it | step 9 |
| 5. One audit event | a certificate valid for at most 1 day on `sp-fns-scout`, the read-only identity | step 7 |
| 6. One sign-in | `sp-fns-scout` signs in once, in a temporary CLI profile | step 6 itself |

- **Time:** about 45 minutes of commands, plus up to 2 hours of waiting in step 8.
- **Cost:** a workspace on the 5 GB/month free tier for a few hours. That is well
  under $0.10.
- **Writes the tool makes:** none. `fns` only runs `scope check`.

**Stop rules:**

- The lab plan in step 2 is not only additions, or the count differs: stop.
- Step 4 is refused: stop after the clean-up (steps 7, 9, 10) and report.
- Step 8 finds nothing after 2 hours: stop after the clean-up and report.

In every stop case, clean up first, then report back.

## 1. Update your checkout and sign in

```powershell
git switch main
git pull
uv run poe setup
az login --tenant <TENANT_ID>
az account set --subscription <SUBSCRIPTION_ID>
az account show --query "{tenant:tenantId, sub:id, user:user.name}" -o table
```

Check that the table shows the lab tenant, the lab subscription and your own lab
account. You need **Global Administrator** or **Security Administrator** in the
tenant (step 4), and **Owner** or **Contributor** on the subscription.

## 2. Rebuild the lab (you approve the apply)

The lab was destroyed, so this is a fresh build with a new random suffix.
`lab/terraform.tfvars` holds IDs only, and you can keep it. To get the $10
budget alert (D7), add `budget_alert_email = "<your address>"` to it. It never
leaves that gitignored file. Leave it out on Azure for Students
(`lab/README.md`, "Cost alert").

```powershell
Get-Content lab\terraform.tfvars                 # tenant, subscription, location, prefix
uv run poe lab-check                             # fmt + validate, no credentials used
uv run poe lab-up                                # review the plan, then type yes
```

**Review the plan before typing `yes`:**

- **36 to add, 0 to change, 0 to destroy** with the defaults;
- **38 to add** if you set `budget_alert_email`;
- **one more** if `github_repository` is set, and **one fewer** if
  `scout_directory_read_all = false`.

Anything else is a stop: answer `no`, and send the plan summary.

```powershell
uv run fns scope check scope.lab.yaml
terraform -chdir=lab output -json resources | ConvertFrom-Json   # the new names
```

`scope check` should show the lab tenant, subscription and `rg-fns-lab`, 17 scout
and 6 prove operations, and an expiry 7 days out. The resource names carry the
new suffix.

## 3. Create the workspace

The workspace goes in its own resource group, in the lab's region, so it can be
removed without touching the lab.

```powershell
$rgId = terraform -chdir=lab output -raw resource_group_id
$location = az group show --ids $rgId --query location -o tsv
az provider register --namespace Microsoft.OperationalInsights --wait
az provider register --namespace Microsoft.Insights --wait
az group create -n rg-fns-logcheck -l $location --tags project=fang-and-scale purpose=lab -o none
az monitor log-analytics workspace create -g rg-fns-logcheck -n law-fns-logcheck -l $location --retention-time 30 -o none
$wsId = az monitor log-analytics workspace show -g rg-fns-logcheck -n law-fns-logcheck --query id -o tsv
$ws = az monitor log-analytics workspace show -g rg-fns-logcheck -n law-fns-logcheck --query customerId -o tsv
$wsId; $ws                                       # a resource ID, then a workspace GUID
```

## 4. Send both Entra categories to it

This is the step that may be refused for licensing. The setting is tenant-level:
the API is ARM's `microsoft.aadiam` provider, not the subscription.

```powershell
$diag = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/fns-logcheck?api-version=2017-04-01-preview"
$body = @{ properties = @{ workspaceId = $wsId; logs = @(
    @{ category = "AuditLogs"; enabled = $true },
    @{ category = "ServicePrincipalSignInLogs"; enabled = $true }
) } } | ConvertTo-Json -Depth 5
$bodyFile = Join-Path $env:TEMP "fns-logcheck-diag.json"
[IO.File]::WriteAllText($bodyFile, $body)
az rest --method put --url $diag --body "@$bodyFile" --query "properties.logs[].{category:category, enabled:enabled}" -o table
$setAt = (Get-Date).ToUniversalTime()
```

**Expected:** a table with both categories and `enabled` = `True`.

**If the `put` fails:**

1. Copy the error text exactly, with any GUIDs replaced by `<guid>`.
2. Try audit logs alone, so that half still gets an answer:

   ```powershell
   $body = @{ properties = @{ workspaceId = $wsId; logs = @(
       @{ category = "AuditLogs"; enabled = $true }
   ) } } | ConvertTo-Json -Depth 5
   [IO.File]::WriteAllText($bodyFile, $body)
   az rest --method put --url $diag --body "@$bodyFile" --query "properties.logs[].{category:category, enabled:enabled}" -o table
   $setAt = (Get-Date).ToUniversalTime()
   ```

3. If that fails too, go to step 9 and report both errors.

Check the setting is in place, and that it is the only one this run made:

```powershell
az rest --method get --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" --query "value[].{name:name, logs:properties.logs[?enabled].category}" -o json
Remove-Item $bodyFile
```

**Wait 15 minutes before step 5**, so the event is not sent before the setting is
live. That figure is a margin; Microsoft's pages don't give a start-up delay.

## 5. Cause one harmless audit event

The event is adding a short-lived certificate to `sp-fns-scout`, the read-only
identity. Step 6 needs that certificate to sign in anyway. Entra logs it as
**"Update application – Certificates and secrets management"**. The scout's
permissions are reads only, so its credential can't change anything.

```powershell
$tenant = az account show --query tenantId -o tsv
$scoutId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
az ad app credential list --id $scoutId --cert -o tsv           # must print nothing
az ad app credential list --id $scoutId -o tsv                  # no client secrets either
```

If either list prints something, **stop**: this runbook did not create it.

```powershell
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$scoutCred = az ad app credential reset --id $scoutId --create-cert --end-date $end --append --display-name fns-logcheck | ConvertFrom-Json
$eventAt = (Get-Date).ToUniversalTime()

$certs = @(az ad app credential list --id $scoutId --cert | ConvertFrom-Json)
$limit = (Get-Date).ToUniversalTime().AddHours(24)
if ($certs.Count -ne 1 -or ([datetime]$certs[0].endDateTime).ToUniversalTime() -gt $limit) {
    Write-Error "STOP: expected exactly one certificate valid for at most 1 day. Go to step 7."
} else {
    "OK: one certificate ($($certs[0].displayName)), ends $($certs[0].endDateTime)"
}
Start-Sleep -Seconds 180                         # new certificates take ~3 minutes (FINDINGS)
```

Continue only after `OK`.

## 6. Cause one service principal sign-in

The scout signs in once, in its own temporary CLI profile, so your own login
can't be used by mistake.

```powershell
$scoutDir = Join-Path $env:TEMP "fns-logcheck-az"
New-Item -ItemType Directory -Force $scoutDir | Out-Null
$env:AZURE_CONFIG_DIR = $scoutDir
az login --service-principal --username $scoutId --certificate $scoutCred.fileWithCertAndPrivateKey --tenant $tenant --allow-no-subscriptions -o none
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table   # type: servicePrincipal
$signInAt = (Get-Date).ToUniversalTime()
az logout
Remove-Item Env:AZURE_CONFIG_DIR
foreach ($i in 1..5) {
    Remove-Item -Recurse -Force $scoutDir -ErrorAction SilentlyContinue
    if (-not (Test-Path $scoutDir)) { break }
    Start-Sleep -Seconds 3
}
Test-Path $scoutDir                                              # must print False
az account show --query "user.name" -o tsv                       # you again, not the scout
```

If the login fails with `AADSTS700027`, the certificate has not propagated yet.
Wait 3 more minutes and repeat only the `az login --service-principal` line. Each
failed attempt is also a sign-in, logged with a non-zero `ResultType`. That is
fine: the query in step 8 shows them.

Run nothing else as the scout.

## 7. Delete the scout certificate

Step 5 checked the list was empty first, so every certificate here is this run's.
Deleting it is a second audit event, which the queries don't count.

```powershell
foreach ($k in @(az ad app credential list --id $scoutId --cert --query "[].keyId" -o tsv)) {
    az ad app credential delete --id $scoutId --key-id $k --cert
}
Remove-Item $scoutCred.fileWithCertAndPrivateKey
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
Test-Path $scoutCred.fileWithCertAndPrivateKey                   # must print False
```

## 8. Check that both arrived (D5: you run the queries and paste the results)

The queries return no IDs, IP addresses or user names, so the output is safe to
paste. Run them in this window, or paste the KQL text into the portal: Log
Analytics workspaces → `law-fns-logcheck` → Logs.

```powershell
az extension add --name log-analytics --upgrade -o none
$since = $setAt.ToString("yyyy-MM-ddTHH:mm:ssZ")

$qTables = "union withsource=Table isfuzzy=true AuditLogs, AADServicePrincipalSignInLogs | where TimeGenerated > datetime($since) | summarize Rows = count() by Table"

$qAudit = "AuditLogs | where TimeGenerated > datetime($since) | where OperationName contains 'Certificates and secrets management' | mv-expand Target = TargetResources | where tostring(Target.displayName) == 'sp-fns-scout' | project TimeGenerated, OperationName, Result, Target = tostring(Target.displayName), By = iff(isnotempty(tostring(InitiatedBy.user.id)), 'user', 'app')"

$qSignIn = "AADServicePrincipalSignInLogs | where TimeGenerated > datetime($since) | where ServicePrincipalName == 'sp-fns-scout' | project TimeGenerated, ServicePrincipalName, ResultType, ClientCredentialType, ResourceDisplayName"
```

Poll every 10 minutes, for at most 2 hours after the sign-in:

```powershell
$deadline = $signInAt.AddHours(2)
do {
    $rows = az monitor log-analytics query -w $ws --analytics-query $qTables -o json | ConvertFrom-Json
    $have = @($rows | Where-Object { [int]$_.Rows -gt 0 } | ForEach-Object { $_.Table })
    $list = if ($have) { $have -join ", " } else { "none yet" }
    "{0:u}  tables with rows: {1}" -f (Get-Date).ToUniversalTime(), $list
    if ($have -contains "AuditLogs" -and $have -contains "AADServicePrincipalSignInLogs") { break }
    Start-Sleep -Seconds 600
} while ((Get-Date).ToUniversalTime() -lt $deadline)

az monitor log-analytics query -w $ws --analytics-query $qTables -o table
az monitor log-analytics query -w $ws --analytics-query $qAudit -o table
az monitor log-analytics query -w $ws --analytics-query $qSignIn -o table
"setting created {0:u}; event {1:u}; sign-in {2:u}" -f $setAt, $eventAt, $signInAt
```

**Expected if both paths work:**

- `qTables` shows both tables with rows.
- `qAudit` shows one row from step 5, with `Result` = `success` and `By` = `user`.
  Rows from step 7 don't match this filter.
- `qSignIn` shows at least one row with `ResultType` = `0` and
  `ClientCredentialType` = `Certificate`.

A query against a table that never received data fails with "Failed to resolve
table". That counts as "no rows" for that table, and is a result in itself:
report it as it is.

## 9. Remove the diagnostic setting and the workspace

Do this whatever the result. `lab-down` does not know about either.

```powershell
az rest --method delete --url $diag
az rest --method get --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" --query "value[].name" -o tsv   # must not list fns-logcheck
az monitor log-analytics workspace delete -g rg-fns-logcheck -n law-fns-logcheck --force true --yes
az group delete -n rg-fns-logcheck --yes
az group exists -n rg-fns-logcheck                               # must print false
```

`--force true` deletes the workspace at once, without the 14-day soft delete.

## 10. Tear down the lab (you approve the destroy)

```powershell
uv run poe lab-down                              # review: destroys what step 2 added; type yes
az group exists -n rg-fns-lab                                    # must print false
foreach ($n in "sp-billing-agent", "app-escalation-target", "id-verifier", "sp-fns-scout") {
    "{0}: {1}" -f $n, (@(az ad app list --display-name $n --query "[].appId" -o tsv).Count)   # each must be 0
}
```

If you set the budget in step 2, `lab-down` removes it too.

## 11. Report back

Paste these:

1. The plan summary line from step 2 (`Plan: N to add, ...`).
2. The step 4 output, or both error texts with GUIDs replaced by `<guid>`.
3. The last line of the polling loop, and the outputs of the three queries in
   step 8.
4. The `setting created / event / sign-in` times line.
5. That steps 7, 9 and 10 printed what they should (empty lists, `False`,
   `false`, and four zeros).

What happens next (`docs/milestones/M4-plan.md`, step 1):

- **Both tables have rows:** D1 stands. I record a FINDINGS entry with the date,
  and the M4 sessions go ahead with no trial.
- **Either is missing or refused:** stop. No strike code is written until you
  choose option a, b, c or d from the M4 plan. I record a FINDINGS entry with the
  exact response either way.

## Emergency cleanup

Run this if the session dies or a step fails midway. Sign in as yourself first
(`az login --tenant <TENANT_ID>`). Every command is safe to repeat.

```powershell
Remove-Item Env:AZURE_CONFIG_DIR -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $env:TEMP "fns-logcheck-az") -ErrorAction SilentlyContinue
$scoutId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
foreach ($k in @(az ad app credential list --id $scoutId --cert --query "[?displayName=='fns-logcheck'].keyId" -o tsv)) {
    az ad app credential delete --id $scoutId --key-id $k --cert
}
az rest --method delete --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/fns-logcheck?api-version=2017-04-01-preview"
az group delete -n rg-fns-logcheck --yes
uv run poe lab-down
```

- **The certificate:** if nobody deletes it, it stops working within 24 hours,
  and `lab-down` deletes the application anyway.
- **The diagnostic setting:** it outlives everything else. Check that the
  `diagnosticSettings` list in step 9 no longer shows `fns-logcheck`.
- **The PEM file:** it is in your user profile, under the name printed by
  `az ad app credential reset`. Delete it if the session died before step 7.
