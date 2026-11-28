# M4 live run: record, strike, harden, prove the fix

> **Not run yet.** Written 2026-11-27 from `docs/milestones/M4-plan.md`
> (sessions A to D) and `docs/milestones/M4-strikes-plan.md`. Every `fns`
> command and every output shown here has been run against the recorded
> fixtures only. Where the live output may differ, the text says so.

> **Commands that prompt** (`az login`, `lab-up`, `lab-down`, `terraform
> -chdir=lab apply`) are each in a block of their own, marked **alone**. Paste
> them **alone**: Terraform reads the next pasted line as the answer to its `yes`
> prompt (FINDINGS), and `az login` may ask you to pick a subscription.

All commands are Windows PowerShell, run from the repository root, **by you**. I
make no Azure call and hold no lab credential. Nothing here is filled in with a
real value. Every ID comes from `terraform output` or from `az` at run time,
apart from the tenant and subscription you type in each session's first blocks.

> Use the **dedicated lab tenant**, as in M1 to M3.

> **Before session A**, go through [`m4-preflight.md`](m4-preflight.md): credit,
> clocks, sleep, Claude Code's mode, what to paste back, stop triggers.

## How to run it

- Every copy-paste block has an ID: **A2b** is the second block of step A2.
  Paste one block, compare what it printed with its **Expect** line, then go on
  to the next.
- A block marked **alone** is one line that prompts. Paste only that line, read
  what it shows, and answer it yourself.
- Lines that say **by hand** are edits or portal checks, not commands.
- Each session starts with its own **0** blocks (sign in, variables, scope) and
  ends with a **Paste back** list. One PowerShell window per session.
- If a block prints something its **Expect** line does not cover, stop there and
  send that block's output.

## What this run does

| Session | What | Creates | Removed in |
| --- | --- | --- | --- |
| A | Rebuild the lab, baseline scout recorded as `fixtures/lab-run-4` | everything in `lab/`, with a new random suffix; a 1-day scout certificate | A4 (certificate); Teardown (lab) |
| B | Monitoring on (workspace, Sentinel, diagnostic settings, the 11 rules); legitimate use as the agent; `fns record` | 18 resources; a 1-day agent certificate | B2 (certificate); Teardown |
| C | `fns strike` S1 to S4, then one KQL query per strike (D5) | 2 resources (the strike expiry, the marker role's ID) and the marker role on `app-escalation-target`; 1-day scout and agent certificates; each strike's writes, all undone by the tool | C5 (certificates); C4 (strike writes); Teardown (marker role) |
| D | Harden, apply, prove the fix, D-1 to D-7 (D6), recorded as `fixtures/lab-run-5` | 1-day certificates; nothing else, unless a D-step succeeds (undone at once) | D8 |
| Teardown | `lab-down`, then the checks | | |

- **Time:** A 1.5 h, B 1 h plus up to a day for logs, C 2 h (mostly waiting
  for alerts), D 1.5 h.
- **Cost:** under $5 if C and D fall inside the 31-day Sentinel trial that B
  starts (`docs/milestones/M4-plan.md`, "Trials, cost and expiry").
- **Clocks:** the scope is valid for 7 days from A2 (`scope_valid_days`); each
  session's **0c** block renews it. The strike window is 4 hours from C1
  (`strike_valid_hours`); D5 renews it. A strike plan expires 1 hour after it
  was made.
- **Writes the tool makes:** only `fns strike run` in C4 and D6. Each write is
  in a plan you approve by its hash, goes only to a lab object, and is undone
  and verified before the command exits.
- **S4** (approved 2026-11-27) runs right after S3, in the same `fns strike
  run`. It asks for a token as `app-escalation-target` with S3's password, which
  is removed as soon as the token is held. As that identity it assigns the marker
  role (defined by Terraform in C1, grants nothing) to the agent, then removes
  the assignment. The token exists only in the tool's memory, for seconds: only
  its `oid` and `roles` claims are journaled.
- **Not in this run:** `harden --apply` is not built: you apply the diff
  yourself.

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

Sessions B, C and D each begin with the same three blocks, **0a** to **0c**
(B0a, C0a, ...); session A has its own A0a and A0b, because the lab does not
exist yet. Each session can run in a new PowerShell window, on another day. Run
them as **yourself**. You need **Global Administrator** (for the Entra
diagnostic setting in B1) and **Owner** on the subscription.

The scope is valid for 7 days from A2 (`scope_valid_days`). The **0b** block
ends with `scope check`: if it says `invalid ... expired`, or less than a day is
left, run **0c** before anything else in the session. Never run 0c between a
strike plan and its run: the plan is bound to the scope file's hash.

## Session A: rebuild the lab

### A0. Start the session

#### A0a · alone

```powershell
az login --tenant <TENANT_ID>
```

**Expect:** a sign-in window; sign in as your own lab account. If it lists
subscriptions and asks for one, pick the lab subscription.

#### A0b

```powershell
az account set --subscription <SUBSCRIPTION_ID>
az account show --query "{tenant:tenantId, sub:id, user:user.name}" -o table
$tenant = az account show --query tenantId -o tsv
$scoutDir = Join-Path $env:TEMP "fns-m4-scout-az"
$agentDir = Join-Path $env:TEMP "fns-m4-agent-az"
```

**Expect:** one table row: the lab tenant, the lab subscription and your own lab
account. Nothing else.

### A1. Update your checkout

#### A1

```powershell
git switch main
git pull
uv run poe setup
```

**Expect:** `main` up to date with `origin/main`; `setup` ends without an
error.

### A2. Rebuild the lab (you approve the apply)

`lab/terraform.tfvars` holds IDs only. Keep `enable_monitoring` and
`enable_strikes` **unset** (both default to `false`) for this session.

#### A2a

```powershell
Get-Content lab\terraform.tfvars                 # tenant, subscription, location, prefix
uv run poe lab-check                             # fmt + validate, no credentials used
```

**Expect:** the four variables and nothing that enables monitoring, strikes or
the budget; `lab-check` ends with `Success! The configuration is valid.`

#### A2b · alone

Paste this line **on its own**, and type the answer yourself:

```powershell
uv run poe lab-up
```

**Expect:** review the plan before typing `yes`:

- **37 to add, 0 to change, 0 to destroy** with the defaults;
- **39 to add** if you set `budget_alert_email`;
- **one more** if `github_repository` is set.

Anything else is a stop: answer `no`, and send the plan summary.

#### A2c

```powershell
uv run fns scope check scope.lab.yaml
terraform -chdir=lab output -json resources | ConvertFrom-Json   # the new names
```

**Expect:** `valid scope.lab.yaml`; the lab tenant, subscription and
`rg-fns-lab`; `operations    prove 6, scout 17` (no `strike`), no `strike` line,
and an expiry 7 days out. Then the three new resource IDs, with a new suffix. Wait about 10
minutes for the Graph grants to show up in tokens.

### A3. Baseline scout as `sp-fns-scout`, recorded as `lab-run-4`

#### A3a

```powershell
$scoutId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
$agent = terraform -chdir=lab output -json billing_agent | ConvertFrom-Json
$agentId = $agent.client_id
$agentOid = $agent.object_id
```

**Expect:** nothing printed.

#### A3b

```powershell
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
az ad app credential list --id $scoutId -o tsv                   # no client secrets either
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$scoutCred = az ad app credential reset --id $scoutId --create-cert --end-date $end --append --display-name fns-m4-scout | ConvertFrom-Json
Start-Sleep -Seconds 180                         # new certificates take ~3 minutes (FINDINGS)
```

**Expect:** the two `list` lines print nothing; the reset may print a warning
about protecting the credential; then 3 minutes of waiting. Anything printed by
a `list` line is a stop.

#### A3c

```powershell
New-Item -ItemType Directory -Force $scoutDir | Out-Null
$env:AZURE_CONFIG_DIR = $scoutDir
az login --service-principal --username $scoutId --certificate $scoutCred.fileWithCertAndPrivateKey --tenant $tenant -o none
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table   # type: servicePrincipal

uv run fns scout --scope scope.lab.yaml --record fixtures/lab-run-4
$snap = (Get-ChildItem .fns\snapshots\*.LIVE.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

**Expect:** `type` `servicePrincipal`; then `LIVE read-only snapshot`, a
Collectors table of 12 collectors: eleven `complete` and `pim.eligibility`
`not-applicable`; `edges:` with `memberOf=1` (the lab group `grp-fns-billing`
(D3) now gives `sp-billing-agent` one `memberOf` entry); `recorded fixture
fixtures/lab-run-4`; and a `digest sha256:` line.

If the login fails with `AADSTS700027`, wait 3 more minutes and repeat only the
`az login --service-principal` line.

### A4. Remove the scout certificate

#### A4a

```powershell
az logout
Remove-Item Env:AZURE_CONFIG_DIR
foreach ($i in 1..5) {   # Windows can hold the profile briefly
    Remove-Item -Recurse -Force $scoutDir -ErrorAction SilentlyContinue
    if (-not (Test-Path $scoutDir)) { break }
    Start-Sleep -Seconds 3
}
# A3 checked the list was empty first, so every certificate here is this run's
foreach ($k in @(az ad app credential list --id $scoutId --cert --query "[].keyId" -o tsv)) {
    az ad app credential delete --id $scoutId --key-id $k --cert
}
Remove-Item $scoutCred.fileWithCertAndPrivateKey
```

**Expect:** nothing printed.

#### A4b

```powershell
Test-Path $scoutDir                                              # must print False
az account show --query "user.name" -o tsv                       # you again, not the scout
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
uv run pytest tests/fixtures/test_no_real_ids.py -q
git status --short fixtures/lab-run-4                            # _idmap.json must NOT be listed
```

**Expect:** `False`; your user name; nothing; the tests pass; `?? fixtures/lab-run-4/`
(or its files), and no `_idmap.json`.

The `Directory.Read.All` and custom-role tests from the M4 plan ("Session A,
continued") are not part of this runbook. They change the scout, not the agent,
and get their own steps when the custom role is built.

### A5. Paste back (session A)

The A2b plan summary line; the A2c `scope check` output; the A3c scout summary;
the A4b results. Replace every GUID first ([Report back](#report-back)).

---

## Session B: monitoring, legitimate use, record

### B0. Start the session

#### B0a · alone

```powershell
az login --tenant <TENANT_ID>
```

**Expect:** a sign-in window; sign in as your own lab account. If it lists
subscriptions and asks for one, pick the lab subscription.

#### B0b

```powershell
az account set --subscription <SUBSCRIPTION_ID>
az account show --query "{tenant:tenantId, sub:id, user:user.name}" -o table
$tenant = az account show --query tenantId -o tsv
$scoutDir = Join-Path $env:TEMP "fns-m4-scout-az"
$agentDir = Join-Path $env:TEMP "fns-m4-agent-az"
$scoutId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
$agent = terraform -chdir=lab output -json billing_agent | ConvertFrom-Json
$agentId = $agent.client_id
$agentOid = $agent.object_id
$mon = terraform -chdir=lab output -json monitoring | ConvertFrom-Json   # null before B1
$ws = $mon.workspace_customer_id
uv run fns scope check scope.lab.yaml            # the "expires" line: time left
```

**Expect:** the table shows the lab tenant, the lab subscription and your own
lab account; `scope check` says `valid` with at least a day left on its
`expires` line. Otherwise run 0c.

#### B0c · alone, only if the scope needs renewing

```powershell
terraform -chdir=lab apply "-replace=time_offset.scope_expiry"
```

**Expect:** the plan: `time_offset.scope_expiry` and `local_file.scope`
replaced, **2 to add, 0 to change, 2 to destroy**. Anything else is a stop. Then
run `uv run fns scope check scope.lab.yaml` again: 7 days left.

### B1. Turn monitoring on (workspace, diagnostic settings, rules)

**By hand:** add this line to `lab/terraform.tfvars`:

```
enable_monitoring = true
```

#### B1a

```powershell
uv run fns detections check                      # every rule against its sample rows
uv run fns detections export --terraform lab/detections.json --check   # up to date
```

**Expect:** `11 rule(s), 0 problem(s)`, then `ok lab/detections.json matches 11
rule(s)`.

#### B1b · alone

Paste this line **on its own**:

```powershell
uv run poe lab-up
```

**Expect:** **The plan must be 18 to add, 0 to change, 0 to destroy**: the
workspace, the Sentinel onboarding, five diagnostic settings (Activity Log, Key
Vault, two blob services, Entra) and 11 scheduled rules. Anything else is a
stop. This apply starts the 31-day Sentinel trial.

#### B1c

```powershell
$mon = terraform -chdir=lab output -json monitoring | ConvertFrom-Json
$ws = $mon.workspace_customer_id
$mon.rules.Count                                 # must print 11
az rest --method get --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" --query "value[].{name:name, logs:properties.logs[?enabled].category}" -o json
```

**Expect:** `11`; then the Entra list shows one setting, ending in `-entra`,
with `AuditLogs` and `ServicePrincipalSignInLogs`.

**By hand:** open the workspace in the **Defender portal** (Microsoft
Sentinel) and check that the free trial shows 31 days. Sessions C and D must fit
inside it. Write down its end date.

### B2. Legitimate use as the agent (by hand)

This is the agent's normal work, which record mode turns into `must_still_do`
items (PLAN §5). The upload is a write, and you make it, not the tool.

#### B2a

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

**Expect:** the three `list` lines print nothing; the reset may print a warning
about protecting the credential; 3 minutes of waiting. A `list` line that prints
anything is a stop.

#### B2b

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

**Expect:** `type` `servicePrincipal`; the download and the upload print nothing
(maybe a progress bar). An `AuthorizationPermissionMismatch` is a stop: the
grant the agent needs for its normal work is missing.

#### B2c

Delete the certificate right away:

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

**Expect:** only `False`, on the last line.

### B3. Export the agent's rows

Wait for the rows: Activity Log within minutes, blob logs within about 15
minutes. These files hold **real IDs**: they stay in `.fns\` (gitignored).
Don't paste them anywhere. `fns record` reads them on your machine.

#### B3a

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

**Expect:** a number, **at least 2** (the download and the upload). If the blob
count is 0, wait 15 minutes and run the last three lines again.

### B4. Record

#### B4a

```powershell
uv run fns record (Join-Path $logs "blob.json") (Join-Path $logs "activity.json") --identity $agentOid --contract contracts\lab\billing-agent.fns.yaml --out .fns\m4\recorded.fns.yaml
```

**Expect,** exit 0:

```
<n> row(s): 2 recorded resource operation(s), 0 failed, <k> by other identities, <u> unmapped
  unmapped StorageBlobLogs:<operation> x<count>
  already declared stinvoices<suffix> blob/read
  already declared stinvoices<suffix> blob/write
wrote .fns/m4/recorded.fns.yaml
```

The lab contract already declares `blob/read` and `blob/write` on the invoices
account (`source: declared`), so the recording confirms them and adds nothing:
`recorded.fns.yaml` is the lab contract. An `added <account> <operation> (source:
recorded)` line is a legitimate operation the contract did not know: send it. A
`CONFLICT` line (exit 1) is a recorded operation the contract forbids: a stop.
Send the output (it names operations and the account, not IDs).

### B5. Paste back (session B)

The B1b plan summary line; the B1c `$mon.rules.Count` and the Entra setting's
name and categories; the trial's end date; the B3a count; the B4a output.

---

## Session C: strikes S1 to S4 and detection results

### C0. Start the session

#### C0a · alone

```powershell
az login --tenant <TENANT_ID>
```

**Expect:** a sign-in window; sign in as your own lab account. If it lists
subscriptions and asks for one, pick the lab subscription.

#### C0b

```powershell
az account set --subscription <SUBSCRIPTION_ID>
az account show --query "{tenant:tenantId, sub:id, user:user.name}" -o table
$tenant = az account show --query tenantId -o tsv
$scoutDir = Join-Path $env:TEMP "fns-m4-scout-az"
$agentDir = Join-Path $env:TEMP "fns-m4-agent-az"
$scoutId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
$agent = terraform -chdir=lab output -json billing_agent | ConvertFrom-Json
$agentId = $agent.client_id
$agentOid = $agent.object_id
$mon = terraform -chdir=lab output -json monitoring | ConvertFrom-Json   # null before B1
$ws = $mon.workspace_customer_id
uv run fns scope check scope.lab.yaml            # the "expires" line: time left
```

**Expect:** the table shows the lab tenant, the lab subscription and your own
lab account; `scope check` says `valid` with at least a day left on its
`expires` line. Otherwise run 0c.

#### C0c · alone, only if the scope needs renewing

```powershell
terraform -chdir=lab apply "-replace=time_offset.scope_expiry"
```

**Expect:** the plan: `time_offset.scope_expiry` and `local_file.scope`
replaced, **2 to add, 0 to change, 2 to destroy**. Anything else is a stop. Then
run `uv run fns scope check scope.lab.yaml` again: 7 days left.

### C1. Turn strikes on

**By hand:** add this line to `lab/terraform.tfvars`:

```
enable_strikes = true
```

#### C1a · alone

Paste this line **on its own**:

```powershell
uv run poe lab-up
```

**Expect:** `time_offset.strike_expiry[0]` and `random_uuid.strike_marker[0]`
are created, `azuread_application.escalation_target` is updated in place (it
gains the marker `app_role`: `fns.strike.marker`, "Grants nothing",
`Application` only), and `local_file.scope` is replaced, because its content
gains the `strike:` block. That is **3 to add, 1
to change, 1 to destroy**.
Anything else is a stop. This apply starts the 4-hour strike window: C3 and C4
must run inside it.

#### C1b

```powershell
uv run fns scope check scope.lab.yaml
terraform -chdir=lab output -raw scope_expires_at
```

**Expect:** `scope check` now prints `operations    prove 6, scout 18, strike 9` (S4 adds
one scout read), a `strike` line with an expiry 4 hours out
(`strike_valid_hours`) and 7 targets, and an `escalation` line (S4's service
principal and the marker role). Then the scope's own expiry, unchanged.

### C2. A certificate for the scout and one for the agent, each in its own profile

The strike signs in **two** identities: the agent writes, and the read-only
scout reads the state before and after (decision of 2026-11-27, two CLI
profiles). Neither profile is used in this window afterwards: `fns` reads each
one for its own token.

#### C2a

```powershell
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
az ad app credential list --id $agentId --cert -o tsv            # must print nothing
az ad app credential list --id $agentId -o tsv                   # must print nothing
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$scoutCred = az ad app credential reset --id $scoutId --create-cert --end-date $end --append --display-name fns-m4-scout | ConvertFrom-Json
$agentCred = az ad app credential reset --id $agentId --create-cert --end-date $end --append --display-name fns-m4-agent | ConvertFrom-Json
Start-Sleep -Seconds 180
```

**Expect:** the three `list` lines print nothing; each reset may print a
warning about protecting the credential; 3 minutes of waiting.

#### C2b

```powershell
New-Item -ItemType Directory -Force $scoutDir, $agentDir | Out-Null
$env:AZURE_CONFIG_DIR = $scoutDir
az login --service-principal --username $scoutId --certificate $scoutCred.fileWithCertAndPrivateKey --tenant $tenant -o none
$env:AZURE_CONFIG_DIR = $agentDir
az login --service-principal --username $agentId --certificate $agentCred.fileWithCertAndPrivateKey --tenant $tenant --allow-no-subscriptions -o none
Remove-Item Env:AZURE_CONFIG_DIR
az account show --query "user.name" -o tsv                       # you, in this window
```

**Expect:** only your own user name, on the last line. An `AADSTS700027`: wait
3 more minutes and run C2b again.

### C3. Plan the strikes (reads only)

#### C3a

```powershell
uv run fns strike plan --strikes S1,S2,S3,S4 --scope scope.lab.yaml --scout-config $scoutDir
$plan = (Get-ChildItem .fns\strike\*\plan.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
(Get-Content $plan | ConvertFrom-Json).writes | ForEach-Object { "{0}  {1} {2}" -f $_.key, $_.request.method, $_.request.url; ($_.request.body | ConvertTo-Json -Compress -Depth 6); "  undo: " + (($_.undo | ForEach-Object { "{0} {1}" -f $_.method, $_.url }) -join "; ") }
```

**Expect:** a `strike plan <run id>: S1, S2, S3, S4` line, a table, a `plan
sha256:` line and `written .fns/strike/<run id>/plan.json`. The table shortens
the URLs, so the last line prints each write in full. **Review every line.**
Expected: five writes, all `allowed`:

| Write | Request | Undo |
| --- | --- | --- |
| `S1/list-keys` | `POST .../storageAccounts/stpayroll<suffix>/listKeys` | `regenerateKey` key1, then key2 (SD1) |
| `S2/vault-tag` | `PATCH .../vaults/kv-crown-<suffix>`, body `tags` only, with `fns-strike` added | `PATCH` the pre-state tags back |
| `S3/add-password` | `POST /applications/<app-escalation-target>/addPassword`, `fns-strike-<run>`, ending within 1 hour | `removePassword` of that `keyId`, right after `S4/token` |
| `S4/token` | `POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`, body `client_id` (`app-escalation-target`'s appId), `grant_type` `client_credentials`, `scope` `https://graph.microsoft.com/.default`, and **no secret** (the tool adds S3's password on the wire only) | none |
| `S4/assign` | `POST /servicePrincipals/<app-escalation-target SP>/appRoleAssignedTo`, `acts_as` `escalated`, body `principalId` the agent, `resourceId` that SP, `appRoleId` the marker | `DELETE` that assignment, as the escalated identity |

Any other target, method or body key is a stop. The plan expires 1 hour after it
was made. If you need longer, plan again.

#### C3b

**Approve:** copy the 64 hex characters after `plan sha256:` from the output.
Typing them is the approval.

```powershell
$hash = "<the 64 hex characters after plan sha256:>"
```

**Expect:** nothing printed.

### C4. Run the strikes (the only writes in session C)

#### C4a

```powershell
$strikeAt = (Get-Date).ToUniversalTime()
uv run fns strike run --plan $plan --approve $hash --scope scope.lab.yaml --agent-config $agentDir --scout-config $scoutDir
$LASTEXITCODE                                    # expected: 0
$cRun = Split-Path $plan
```

**Expect** (the fixture run, `fns strike run --fixture fixtures/strike-demo`,
prints the same shape, each line prefixed `FIXTURE`):

```
strike run <run id> (plan sha256:<hash>)
+-----------------------------------------------------------+
| write           | expect  | outcome   | status | undo     |
|-----------------+---------+-----------+--------+----------|
| S1/list-keys    | allowed | succeeded | 200    | 200, 200 |
| S2/vault-tag    | allowed | succeeded | 200    | 200      |
| S3/add-password | allowed | succeeded | 200    | 204      |
| S4/token        | allowed | succeeded | 200    | -        |
| S4/assign       | allowed | succeeded | 201    | 204      |
+-----------------------------------------------------------+
verify ok   credentials <app>: as before
verify ok   tags <vault>: as before
verify ok   keys <payroll account>: both regenerated
verify ok   app role assignments <app-escalation-target SP>: as before
exit 0: clean: every write undone and verified
written .fns/strike/<run id>/strike-run.json
0
```

The fixture recording has S1 to S3 only (`fns strike plan --fixture` refuses
S4: a recording can't replay a token exchange), so the two S4 rows are the shape
the tests show against the fake tenant.

The keys from `listKeys`, the password from `addPassword` and S4's token are
never printed, journaled or written to disk: the transport strips them first.
For the token, the journal holds only its `oid` and `roles` claims.

- **`S4/token` `failed`:** the token's claims did not prove the capability
  (`oid` not `app-escalation-target`'s service principal, or `roles` without
  `AppRoleAssignment.ReadWrite.All`). Nothing was assigned and S3's password is
  already removed. That is a FINDINGS entry, not a stop.
- **`needs-emergency-cleanup` in the undo column:** the marker assignment is
  still there and only the token could have removed it. Go to
  [Emergency cleanup](#emergency-cleanup), step 2, "S4".

- **Exit 2:** bad input (a path, an option, an expired plan file); nothing was
  sent. Send the message.
- **Exit 4:** the scope gate or the plan check refused. Everything before it was
  undone. Send the message.
- **Exit 5, or any `verify FAIL`:** go to [Emergency cleanup](#emergency-cleanup)
  now.
- A `403` where `allowed` was expected is a FINDINGS entry (the permission the
  strike plan assumed is not the one Azure checks).

### C5. Sign both identities out and delete their certificates (immediately)

#### C5a

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

**Expect:** nothing printed.

#### C5b

**Verify. Every line must print nothing, or `False`:**

```powershell
az ad app credential list --id $agentId --cert -o tsv
az ad app credential list --id $agentId -o tsv
az ad app credential list --id $scoutId --cert -o tsv
Test-Path $agentDir
Test-Path $scoutDir
Test-Path $agentCred.fileWithCertAndPrivateKey
```

**Expect:** `False` three times, and nothing else. Anything else: [Emergency
cleanup](#emergency-cleanup), step 3.

### C6. Detection results: one query per strike (D5)

The queries return no IDs, IP addresses or user names, so their output is safe to
paste. The identities are used only in `where`, never in the output.

#### C6a

```powershell
$since = $strikeAt.AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ssZ")

$qS1 = "AzureActivity | where TimeGenerated > datetime($since) | where Caller in~ ('$agentOid', '$agentId') | where OperationNameValue in~ ('MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION', 'MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION') | project TimeGenerated, OperationNameValue, ActivityStatusValue"

$qS2 = "AzureActivity | where TimeGenerated > datetime($since) | where Caller in~ ('$agentOid', '$agentId') | where OperationNameValue =~ 'MICROSOFT.KEYVAULT/VAULTS/WRITE' | project TimeGenerated, OperationNameValue, ActivityStatusValue"

$qS3 = "AuditLogs | where TimeGenerated > datetime($since) | where OperationName contains 'Certificates and secrets management' | mv-expand Target = TargetResources | where tostring(Target.displayName) == 'app-escalation-target' | mv-apply P = Target.modifiedProperties on (summarize Before = sumif(array_length(todynamic(tostring(P.oldValue))), tostring(P.displayName) == 'KeyDescription'), After = sumif(array_length(todynamic(tostring(P.newValue))), tostring(P.displayName) == 'KeyDescription')) | project TimeGenerated, OperationName, Result, Change = case(After > Before, 'add', After < Before, 'delete', 'unknown'), By = iff(isnotempty(tostring(InitiatedBy.app.servicePrincipalId)), 'app', 'user')"

$qS4 = "AuditLogs | where TimeGenerated > datetime($since) | where OperationName in ('Add app role assignment to service principal', 'Remove app role assignment from service principal') | where TargetResources has '$agentOid' | project TimeGenerated, OperationName, Result, By = iff(isnotempty(tostring(InitiatedBy.app.servicePrincipalId)), 'app', 'user')"

$qAlerts = "SecurityAlert | where TimeGenerated > datetime($since) | where AlertName startswith 'fns: ' | summarize First = min(TimeGenerated), Alerts = count() by AlertName"
```

**Expect:** nothing printed.

#### C6b

Poll every 10 minutes, for at most 2 hours after the strike:

```powershell
$deadline = $strikeAt.AddHours(2)
do {
    $rows = az monitor log-analytics query -w $ws --analytics-query $qAlerts -o json | ConvertFrom-Json
    $alerts = @($rows | Where-Object { $_ })     # one item per alert, in 5.1 and 7
    "{0:u}  alerts: {1}" -f (Get-Date).ToUniversalTime(), (@($alerts | ForEach-Object { $_.AlertName }) -join "; ")
    if ($alerts.Count -ge 4) { break }
    Start-Sleep -Seconds 600
} while ((Get-Date).ToUniversalTime() -lt $deadline)
```

**Expect:** one `<time>  alerts: ...` line every 10 minutes, the list growing;
it stops at four alert names, or after 2 hours. Keep the laptop awake.

#### C6c

```powershell
az monitor log-analytics query -w $ws --analytics-query $qS1 -o table
az monitor log-analytics query -w $ws --analytics-query $qS2 -o table
az monitor log-analytics query -w $ws --analytics-query $qS3 -o table
az monitor log-analytics query -w $ws --analytics-query $qS4 -o table
az monitor log-analytics query -w $ws --analytics-query $qAlerts -o table
"strike run started {0:u}" -f $strikeAt
```

**Expect:**

| Strike | Query | Rows | Rule that should fire (`AlertName`) |
| --- | --- | --- | --- |
| S1 | `qS1` | `LISTKEYS/ACTION` and two `REGENERATEKEY/ACTION`, `Success` | `storage-listkeys-by-workload`: "fns: Storage account keys listed by a monitored workload" |
| S2 | `qS2` | two `VAULTS/WRITE`, `Success` (the tag and its undo) | `keyvault-control-plane-write-by-workload`: "fns: Key Vault configuration changed by a monitored workload" |
| S3 | `qS3` | two rows, `By` = `app`: `Change` = `add`, then `delete` (the undo) | `app-credential-added-by-workload`: "fns: Credential added to an application or service principal by a workload identity" |
| S4 | `qS4` | `Add app role assignment to service principal`, then `Remove app role assignment from service principal` (the undo), both `By` = `app` | `app-role-assignment-by-workload`: "fns: Graph app role granted by a workload identity" |

**Detection result per strike:** fired or not, and `First` minus the strike
time. A strike whose rows arrived but whose rule did not fire within 2 hours is
a `detection-gap` (PLAN §4). That is a result, not a stop.

- The `SecurityAlert` query has not run live yet. If it fails, or stays empty
  while the rows are there, open **Incidents** in the Defender portal and paste
  the alert names and times it shows.
- The rules run every 15 minutes over the last hour, so up to about 30 minutes on
  top of the log delay is normal.

### C7. Paste back (session C)

The C1a plan summary line; the C1b `operations`, `strike` and `escalation` lines
(IDs replaced); the C3a review lines **with the IDs replaced by the lab names**;
the full C4a output, its IDs replaced the same way, and `$LASTEXITCODE`; the C5b
checks; the five C6c outputs and the start time.

---

## Session D: harden, apply, prove the fix, D-1 to D-7

### D0. Start the session

#### D0a · alone

```powershell
az login --tenant <TENANT_ID>
```

**Expect:** a sign-in window; sign in as your own lab account. If it lists
subscriptions and asks for one, pick the lab subscription.

#### D0b

```powershell
az account set --subscription <SUBSCRIPTION_ID>
az account show --query "{tenant:tenantId, sub:id, user:user.name}" -o table
$tenant = az account show --query tenantId -o tsv
$scoutDir = Join-Path $env:TEMP "fns-m4-scout-az"
$agentDir = Join-Path $env:TEMP "fns-m4-agent-az"
$scoutId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
$agent = terraform -chdir=lab output -json billing_agent | ConvertFrom-Json
$agentId = $agent.client_id
$agentOid = $agent.object_id
$mon = terraform -chdir=lab output -json monitoring | ConvertFrom-Json   # null before B1
$ws = $mon.workspace_customer_id
uv run fns scope check scope.lab.yaml            # the "expires" line: time left
```

**Expect:** the table shows the lab tenant, the lab subscription and your own
lab account; `scope check` says `valid` with at least a day left on its
`expires` line. Otherwise run 0c.

#### D0c · alone, only if the scope needs renewing

```powershell
terraform -chdir=lab apply "-replace=time_offset.scope_expiry"
```

**Expect:** the plan: `time_offset.scope_expiry` and `local_file.scope`
replaced, **2 to add, 0 to change, 2 to destroy**. Anything else is a stop. Then
run `uv run fns scope check scope.lab.yaml` again: 7 days left.

### D1. Scout and contain

Sign the scout in again, in its own profile (A3 shows the full step).

#### D1a

```powershell
az ad app credential list --id $scoutId --cert -o tsv            # must print nothing
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$scoutCred = az ad app credential reset --id $scoutId --create-cert --end-date $end --append --display-name fns-m4-scout | ConvertFrom-Json
Start-Sleep -Seconds 180
```

**Expect:** the `list` line prints nothing; the reset may print a warning about
protecting the credential; 3 minutes of waiting.

#### D1b

```powershell
New-Item -ItemType Directory -Force $scoutDir | Out-Null
$env:AZURE_CONFIG_DIR = $scoutDir
az login --service-principal --username $scoutId --certificate $scoutCred.fileWithCertAndPrivateKey --tenant $tenant -o none
uv run fns scout --scope scope.lab.yaml
Remove-Item Env:AZURE_CONFIG_DIR
$snap = (Get-ChildItem .fns\snapshots\*.LIVE.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
uv run fns contain --contract .fns\m4\recorded.fns.yaml --snapshot $snap
```

**Expect:** the scout summary as in A3c; then `critical reachable: 11/0 max`, as
in lab-run-3, give or take the lab group from D3, which adds an edge but no
role, and `contract FAILED (exit 1)`. Send the summary either way; only a
`must_still_do` failure is a stop here. The scout stays signed in, in its own
profile, for D6.

### D2. Propose the fix

#### D2a

```powershell
uv run fns harden --contract .fns\m4\recorded.fns.yaml --snapshot $snap --out harden.diff
Get-Content harden.diff
```

**Expect:** remove exactly two grants:

- `azurerm_role_assignment.billing_agent_rg_contributor` (Contributor on the RG);
- `azuread_app_role_assignment.billing_agent_owned_by` (Graph
  `Application.ReadWrite.OwnedBy`).

The model goes to 0 critical reachable (`before: critical reachable 11`, `after:
critical reachable 0`), with `blob/read` and `blob/write` on `st-invoices` still
allowed (`legitimate use allowed 2` before and after). Then a `plan sha256:`
line and `wrote harden.diff (not applied)`. Anything else is a stop. Send the
proposal and its `plan sha256:` line.

### D3. Apply the diff (you, not the tool)

#### D3a

```powershell
git switch -c m4-harden
git apply harden.diff
git diff --stat
```

**Expect:** `Switched to a new branch 'm4-harden'`; `git apply` prints nothing;
`lab/identities.tf` and `lab/resources.tf` changed, deletions only.

#### D3b · alone

Paste this line **on its own**:

```powershell
uv run poe lab-up
```

**Expect:** **The plan must be 0 to add, 0 to change, 2 to destroy**, and the two are the
grants in D2. Anything else is a stop: answer `no`.

### D4. A fresh scout: the model says 0

#### D4a

The scout records `fixtures/lab-run-5`: D7's `prove --record` adds its probes to
that recording, and refuses a directory with no scout recording in it.

```powershell
$env:AZURE_CONFIG_DIR = $scoutDir
uv run fns scout --scope scope.lab.yaml --record fixtures/lab-run-5
Remove-Item Env:AZURE_CONFIG_DIR
$snap = (Get-ChildItem .fns\snapshots\*.LIVE.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
uv run fns contain --contract .fns\m4\recorded.fns.yaml --snapshot $snap
```

**Expect:** `recorded fixture fixtures/lab-run-5`, then **0 critical
reachable**. Wait 10 minutes: removed grants can stay in cached tokens for a
while.

#### D4b

**Precondition for D6 and D7: PIM eligibility is a closed surface** (approved
2026-11-27). D7 proves against this snapshot, and an open `pim-eligibility`
surface keeps every application item `inconclusive`, whatever the D-steps show.

```powershell
$cov = (Get-Content $snap -Raw | ConvertFrom-Json).coverage
$cov.collectors | Where-Object name -eq "pim.eligibility" | Select-Object name, status
$cov.not_collected | Where-Object surface -eq "pim-eligibility"          # must print nothing
($cov.not_applicable | Where-Object surface -eq "pim-eligibility").evidence
```

**Expect:** `pim.eligibility` with status `complete`, or `not-applicable` with its
evidence lines (the eligibility listings' responses and `/subscribedSkus`), as in
M2 and M3. Anything else is a stop: no `pim.eligibility` row (it did not run),
`partial`, `failed` or `skipped`, a `pim-eligibility` row in `not_collected`, or
`not-applicable` with no evidence. Send the four outputs.

### D5. Renew the strike expiry

#### D5a

```powershell
uv run fns scope check scope.lab.yaml
```

**Expect:** read its `strike` line. Renew (D5b) if it says `expired`, or less
than 1 hour left: almost always, unless D follows C1 within 4 hours. Otherwise
go to D6.

#### D5b · alone

Paste this line **on its own**:

```powershell
terraform -chdir=lab apply "-replace=time_offset.strike_expiry[0]"
```

**Expect:** the plan: `time_offset.strike_expiry[0]` and `local_file.scope` replaced, **2
to add, 0 to change, 2 to destroy**. Then `scope check` again: a `strike` line
with 4 hours left.

### D6. D-1 to D-7: every attempt must be denied

#### D6a

```powershell
az ad app credential list --id $agentId --cert -o tsv            # must print nothing
az ad app credential list --id $agentId -o tsv                   # must print nothing
$end = (Get-Date).ToUniversalTime().AddHours(23).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$agentCred = az ad app credential reset --id $agentId --create-cert --end-date $end --append --display-name fns-m4-agent | ConvertFrom-Json
Start-Sleep -Seconds 180
```

**Expect:** the two `list` lines print nothing; the reset may print a warning
about protecting the credential; 3 minutes of waiting.

#### D6b

```powershell
New-Item -ItemType Directory -Force $agentDir | Out-Null
$env:AZURE_CONFIG_DIR = $agentDir
az login --service-principal --username $agentId --certificate $agentCred.fileWithCertAndPrivateKey --tenant $tenant --allow-no-subscriptions -o none
Remove-Item Env:AZURE_CONFIG_DIR

uv run fns strike plan --strikes D-1,D-2,D-3,D-4,D-5,D-6,D-7 --scope scope.lab.yaml --scout-config $scoutDir
$plan = (Get-ChildItem .fns\strike\*\plan.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
(Get-Content $plan | ConvertFrom-Json).writes | ForEach-Object { "{0}  {1} {2}" -f $_.key, $_.request.method, $_.request.url; ($_.request.body | ConvertTo-Json -Compress -Depth 6); "  undo: " + (($_.undo | ForEach-Object { "{0} {1}" -f $_.method, $_.url }) -join "; ") }
```

**Expect:** a plan table, a `plan sha256:` line and the full writes. **Review.**
Expected: seven writes, all `expect denied`:

| Write | Request | Undo, only if it succeeds |
| --- | --- | --- |
| `D-1/add-password` | `addPassword` on `app-escalation-target` | `removePassword` |
| `D-2/add-password` | `addPassword` on `id-verifier` | `removePassword` |
| `D-3/add-password` | `addPassword` on `sp-fns-scout` | `removePassword` |
| `D-4/add-owner` | `owners/$ref` on `id-verifier`, the agent as owner | `DELETE .../owners/<agent>/$ref` |
| `D-5/add-owner` | `owners/$ref` on `sp-fns-scout`, the agent as owner | the same, on the scout app |
| `D-6/list-keys` | `POST .../storageAccounts/stpayroll<suffix>/listKeys` | `regenerateKey` key1, then key2 (as SD1) |
| `D-7/list-keys` | `POST .../storageAccounts/stinvoices<suffix>/listKeys` | the same, on the invoices account |

#### D6c

```powershell
$hash = "<the 64 hex characters after plan sha256:>"
uv run fns strike run --plan $plan --approve $hash --scope scope.lab.yaml --agent-config $agentDir --scout-config $scoutDir
$LASTEXITCODE                                    # expected: 0
$dRun = Split-Path $plan
```

**Expect:** every row `denied`, `403`, undo `-`; seven `verify ok` lines, two
of them `keys <account>: unchanged (listKeys not sent)`; `exit 0: clean: every
write undone and verified`; then `0`.

- **Exit 1:** an attempt succeeded. It was undone at once, and the contract
  fails. A `listKeys` that succeeds (D-6, D-7) has both of that account's keys
  regenerated at once, and its `verify` line reads `both regenerated`. This is a
  stop: finish D7 and D8 so the evidence is recorded, then report. It is a
  FINDINGS entry.
- **Exit 2, 4 or 5:** as in C4.

### D7. Prove the fix as the agent, with the D-1 to D-7 evidence

#### D7a

`--after-strike` adds each D-step's result to the finding it observes
(`docs/DECISIONS.md`: D6, and option B, approved 2026-11-27). A D-step counts like
an observed probe denial only if it is LIVE, a 403, on the item's exact operation
and object (`docs/milestones/M4-exit-gate-plan.md`). Every other result is context,
or fails the finding. It refuses a strike run from another tenant, another plan
or another mode before anything is recorded.

```powershell
$env:AZURE_CONFIG_DIR = $agentDir
az account show --query "{tenant:tenantId, type:user.type}" -o table   # type: servicePrincipal
uv run fns prove --contract .fns\m4\recorded.fns.yaml --snapshot $snap --live --scope scope.lab.yaml --record fixtures/lab-run-5 --identity local-verifier --after-strike $dRun
$LASTEXITCODE
az logout
Remove-Item Env:AZURE_CONFIG_DIR
```

**Expect:** `type` `servicePrincipal`, then:

| Item | Expected verdict | Why |
| --- | --- | --- |
| Key Vault `secrets/get`, `secrets/list`; payroll `blob/read` | **`pass`**, `verified` | observed denied, no path left |
| invoices `blob/read` (must still do) | **`pass`**, `verified` | observed allowed |
| `application:id-verifier`, `application:sp-fns-scout` (`credentials/update`, `owners/update`) | **`pass`**, `verified`, the D-step's 403 as supporting evidence; reason "denied by an after-harden strike (D-2) (observed), and every modeled path is refuted" (D-3, D-4, D-5 likewise) | option B: a LIVE 403 on the exact operation and object, no path, and no open surface (D4's PIM check) |
| `directory:tenant applications/credentials/update` | **`inconclusive`**, D-2's `denied` attached as context | D-2 is one application, not every application (approved 2026-11-27) |
| `directory:tenant roleAssignments/write` | **`inconclusive`** | SD3: no direct attempt; never counts |
| payroll `listKeys`, invoices `listKeys` | **`pass`**, `verified`, D-6's (D-7's) 403 as supporting evidence | option B: `listKeys` is in the exact-operation table (approved 2026-11-27), on the account's exact ARM ID |
| invoices `blob/write` (must still do) | **`inconclusive`** | allowed when evaluated; an observed success needs a write, which `prove` never makes |

So expect **exit 0**, `WITHIN BUDGET`, only if those three are the **only**
inconclusive items and no surface is open. The lab contract's budget (approved
2026-11-27) is `max_inconclusive: 3` and names exactly them in
`accepted_inconclusive`, each with its reason: invoices `blob/write` (writes stay
rung 2 by design), `directory:tenant applications/credentials/update` (one app's
denial isn't tenant-wide) and `directory:tenant roleAssignments/write` (SD3).
Option B moves the four application items and the two `listKeys` items to `pass`
(`tests/prove/test_session_d_budget.py`).

- **Exit 3** with a `not accepted by the budget: <item>` line: another item is
  inconclusive. That is a stop, even when the count is 3 or less. The usual
  causes: a D-step that did not print `denied` and `403` in D6, or an open
  surface (D4's PIM check). Send its reasons.
- **Exit 1**, or any finding that **fails**: a stop. Send the reasons.

### D8. Sign out and delete the certificates

Run C5 again: C5a signs out both profiles and deletes both certificates. Then
run C5b. Every line must print nothing, or `False`.

#### D8a

Check the recording:

```powershell
uv run pytest tests/fixtures/test_no_real_ids.py -q
git status --short fixtures/lab-run-5                            # _idmap.json must NOT be listed
```

**Expect:** the tests pass; `fixtures/lab-run-5` listed as new, with no
`_idmap.json`.

Don't commit `lab-run-4` or `lab-run-5` yourself. Each goes in its own PR, after
my checks.

### D9. Paste back (session D)

The D1b contain summary; the D2a harden proposal and its `plan sha256:` line;
the D3b plan summary; the D4a contain summary and the four D4b outputs; the D5b
plan summary, if you ran it; the D6c run output (IDs replaced); the D7a output
and exit code; the D8 checks.

---

## Teardown

Once every fixture is committed. In a new window, run D0a and D0b first.

#### T1 · alone

Paste this line **on its own**, check that it
destroys what A2, B1 and C1 added, less the two grants D3 removed: **55 to
destroy** with the defaults (37 + 18 + 2 - 2; 2 more with `budget_alert_email`,
1 more with `github_repository`). Then type `yes`:

```powershell
uv run poe lab-down
```

**Expect:** `Destroy complete! Resources: 55 destroyed.` (with the defaults).

#### T2

```powershell
az group exists -n rg-fns-lab                                    # must print false
foreach ($n in "sp-billing-agent", "app-escalation-target", "id-verifier", "sp-fns-scout") {
    "{0}: {1}" -f $n, (@(az ad app list --display-name $n --query "[].appId" -o tsv).Count)   # each must be 0
}
az rest --method get --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" --query "value[].name" -o tsv   # must list nothing ending in -entra
Remove-Item -Recurse -Force .fns\m4\logs
git restore lab/identities.tf lab/resources.tf                   # undo D3's git apply
git switch main
git status --short lab                                           # must print nothing
```

**Expect:** `false`; four lines ending in `: 0`; no name ending in `-entra`;
`Switched to branch 'main'`, and nothing from the last line.

**By hand:** set `enable_monitoring` and `enable_strikes` back to `false` (or
remove the lines) in `lab/terraform.tfvars`. The Sentinel trial ends with the
workspace.

**Paste back:** that every T2 check printed what it should.

## Report back

Replace every GUID (tenant, subscription, object and app IDs) with the lab name
or `<id>` first (`docs/runbooks/m4-preflight.md`, section 5). Each session ends
with its own list: [A5](#a5-paste-back-session-a), [B5](#b5-paste-back-session-b),
[C7](#c7-paste-back-session-c), [D9](#d9-paste-back-session-d), and Teardown's.
Per session, paste:

- **A:** the plan summary line; the `scope check` output; the scout summary.
- **B:** the plan summary line; `$mon.rules.Count`; the `fns record` output.
- **C:** the plan summary line; the C3 review lines **with the IDs replaced by
  the lab names**; the full `fns strike run` output, its IDs replaced the same way; `$LASTEXITCODE`; the C5
  checks; the five query outputs and the start time from C6.
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

It **cannot** undo `S4/assign`: only S4's token could, and that token was never
kept. It prints `needs-emergency-cleanup` for it and exits 5 until step 2's S4
block has removed the assignment. Run step 1 again afterwards: exit 0 means
everything is back and verified.

In a new window, run the session's 0a and 0b blocks (for example D0a and D0b)
first, and set `$hash` again: it is the `plan sha256:` line the plan
printed, or, if the run finished, `plan_hash` in its `strike-run.json`.

#### E1a

```powershell
$plan = (Get-ChildItem .fns\strike\*\plan.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
$journal = Join-Path (Split-Path $plan) "journal.sqlite"
$run = Join-Path (Split-Path $plan) "strike-run.json"
if (Test-Path $run) { (Get-Content $run | ConvertFrom-Json).plan_hash }   # the hash, if the run finished
$hash                                            # empty: set it, $hash = "<the 64 hex characters>"
```

**Expect:** the plan's hash, then `$hash` again; set `$hash` if it is empty.

#### E1b

```powershell
uv run fns strike cleanup --plan $plan --approve $hash --journal $journal --scope scope.lab.yaml --agent-config $agentDir --scout-config $scoutDir
$LASTEXITCODE                                    # 0: clean and verified; go to step 3
```

**Expect:** a `cleanup <run id>` table, `verify ok` lines and `0`: go to step 3.
Exit 5 with `needs-emergency-cleanup`: step 2's S4 block, then E1b again.

To see what the journal holds (no bodies or secrets are in it):

#### E1c

```powershell
uv run python -I -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); [print(*r) for r in c.execute('select write_key, phase, at from strike_events order by id')]" $journal
```

**Expect:** one line per event. A write whose last phase is `result` or `error`,
with no `undo-result` after it, still needs its undo.

### 2. Undo by hand, as yourself

Each block is safe to run even if that strike never ran.

#### E2a

```powershell
$res = terraform -chdir=lab output -json resources | ConvertFrom-Json
$agent = terraform -chdir=lab output -json billing_agent | ConvertFrom-Json
$apps = @{}
foreach ($n in "app-escalation-target", "id-verifier", "sp-fns-scout") { $apps[$n] = az ad app list --display-name $n --query "[0].appId" -o tsv }
```

**Expect:** nothing printed.

**S3 and D-1 to D-3: strike passwords.** Delete every password named
`fns-strike-*` on the three apps:

#### E2b

```powershell
foreach ($n in $apps.Keys) {
    foreach ($k in @(az ad app credential list --id $apps[$n] --query "[?starts_with(displayName, 'fns-strike-')].keyId" -o tsv)) {
        az ad app credential delete --id $apps[$n] --key-id $k
    }
    "{0}: {1}" -f $n, (@(az ad app credential list --id $apps[$n] --query "[?starts_with(displayName, 'fns-strike-')]" -o tsv).Count)   # each must be 0
}
```

**Expect:** three lines ending in `: 0`.

**D-4 and D-5: the agent as owner of `id-verifier` or `sp-fns-scout`.** Never
remove it from `app-escalation-target`: it owns that one by design (M2).

#### E2c

```powershell
foreach ($n in "id-verifier", "sp-fns-scout") {
    if (@(az ad app owner list --id $apps[$n] --query "[?id=='$($agent.object_id)']" -o tsv).Count -gt 0) {
        az ad app owner remove --id $apps[$n] --owner-object-id $agent.object_id
    }
    "{0}: {1}" -f $n, (@(az ad app owner list --id $apps[$n] --query "[?id=='$($agent.object_id)']" -o tsv).Count)   # each must be 0
}
```

**Expect:** two lines ending in `: 0`.

**S4: the marker role assignment.** Delete every assignment of the marker role
on `app-escalation-target`'s service principal. The marker grants nothing, but
it is a strike write and must not stay. As yourself, not as the agent:

#### E2d

```powershell
$escSp = (terraform -chdir=lab output -json identities | ConvertFrom-Json).escalation_target
$marker = az ad app show --id $apps["app-escalation-target"] --query "appRoles[?value=='fns.strike.marker'].id | [0]" -o tsv
if ($marker) {
    foreach ($a in @(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$escSp/appRoleAssignedTo" --query "value[?appRoleId=='$marker'].id" -o tsv)) {
        az rest --method delete --url "https://graph.microsoft.com/v1.0/servicePrincipals/$escSp/appRoleAssignedTo/$a"
    }
    @(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$escSp/appRoleAssignedTo" --query "value[?appRoleId=='$marker']" -o tsv).Count   # must be 0
}
```

**Expect:** `0`, or nothing if strikes were never turned on.

**S2: the vault tag.** Remove only the `fns-strike` tag:

#### E2e

```powershell
$v = az keyvault show --ids $res.key_vault --query "tags.\"fns-strike\"" -o tsv
if ($v) { az tag update --resource-id $res.key_vault --operation Delete --tags "fns-strike=$v" -o none }
az keyvault show --ids $res.key_vault --query tags -o json       # project and purpose only
```

**Expect:** tags with `project` and `purpose` only.

**S1 and D-6: the payroll keys.** Make any key the strike read worthless:

#### E2f

```powershell
$payroll = ($res.storage_payroll -split "/")[-1]
az storage account keys renew -g rg-fns-lab -n $payroll --key primary -o none
az storage account keys renew -g rg-fns-lab -n $payroll --key secondary -o none
```

**Expect:** nothing printed.

**D-7: the invoices keys.** Only if D-7 printed anything but `denied`:

#### E2g

```powershell
$invoiceAcct = ($res.storage_invoices -split "/")[-1]
az storage account keys renew -g rg-fns-lab -n $invoiceAcct --key primary -o none
az storage account keys renew -g rg-fns-lab -n $invoiceAcct --key secondary -o none
```

**Expect:** nothing printed.

If the journal is lost, these blocks are also the search by name. They look for
every credential named `fns-strike-*`, any owner reference to the agent on the
two apps, every assignment of the marker role, and the vault tag `fns-strike`.

### 3. Delete the certificates and the profiles

#### E3a

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

**Expect:** nothing printed.

The PEM files are in your user profile, under the names `az ad app credential
reset` printed. Delete them if the session died before C5 or D8.

### 4. If nothing else works

Last, on its own line (it prompts). The strikes write only to lab objects, so
destroying the lab removes everything a strike can touch:

#### E4 · alone

```powershell
uv run poe lab-down
```

**Expect:** the Teardown plan; type `yes`. Then run Teardown's T2 checks.

- **A certificate:** if nobody deletes it, it stops working within 24 hours, and
  `lab-down` deletes the application anyway.
- **A strike password:** it ends 1 hour after it was made (the gate refuses a
  longer one). S3's is removed as soon as S4 holds its token.
- **The marker role assignment:** it grants nothing, and `lab-down` deletes the
  application that defines it.
- **The Entra diagnostic setting:** it is tenant-level. Check, as in Teardown,
  that it is gone.
