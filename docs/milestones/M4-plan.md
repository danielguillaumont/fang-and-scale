# M4 live plan: record, harden, prove the fix, detections

**Status: decisions D1 to D8 approved on 2026-11-26 (end of this file). D1
changed: step 1 is now a log path check. Step 1 PASSED on 2026-11-27: both log
categories reach Log Analytics on Entra ID Free, so D1 stands and no trial is
needed. The strike plan is `docs/milestones/M4-strikes-plan.md` (approved; the
write gate is built). Sessions A to D have not run.** Written 2026-11-26, after the repository went public and the lab was torn
down. The spec is `docs/milestones/M4.md` (K1 to K5). This file is
the live half: what runs in the tenant, in what order, who does each step, what
it costs, and what has to be built first.

## Goal and exit gate

M4 is done when, on a freshly built lab:

1. **Record.** `fns record` turns real Log Analytics rows from the agent's
   legitimate use into `must_still_do` items (`source: recorded`).
2. **Harden.** `fns harden` proposes the smallest Terraform diff that turns the
   recorded contract green in the model, with legitimate use kept.
3. **Prove the fix.** After you apply that diff, a live `fns prove` as the agent
   shows the result at rung 3: the forbidden reads are **observed** denied, the
   invoices read is **observed** allowed, and no escalation path remains.
4. **Detect.** Each of the four K5 strikes has a KQL rule deployed in Sentinel,
   and a recorded detection result: fired, with its latency, or
   `detection-gap`.

Each live run is recorded, sanitized and committed as a fixture
(`fixtures/lab-run-4`, plus `lab-run-5` after harden), and replayed as a
regression test, as in M1 to M3.

## What the recordings already tell us

`fns harden` on the lab-run-3 replay (offline, today) proposes removing two
grants:

- `azurerm_role_assignment.billing_agent_rg_contributor` (Contributor on the RG);
- `azuread_app_role_assignment.billing_agent_owned_by` (Graph
  `Application.ReadWrite.OwnedBy`).

The model then goes from 11 critical reachable to **0**, with both legitimate
operations still allowed. It searched 45 combinations of 9 levers. The
alternative it lists is the `escalation_target` ownership plus Contributor.

Two consequences shape the order of the plan:

- **The strikes must run before harden.** The four K5 strikes need exactly the
  rights harden removes: Contributor for `listKeys` and the vault write, and
  ownership plus `OwnedBy` for the credential and the app role. After harden
  they can only be denied.
- **Harden alone does not make every item pass.** A `must_not_reach` item passes
  only with an observed denial. M3 has read probes for the Key Vault and
  storage items. The directory and application items
  (`roleAssignments/write`, `applications/credentials/update`,
  `credentials/update`, `owners/update`) have no read-only probe, so after
  harden they are refuted in the model but never observed. Under today's rules
  they stay `inconclusive`, and the contract's `max_inconclusive: 2` fails on
  more than 2. Decision D6 covers this.

## Step 1: the log path check (D1, before anything else)

**PASSED on 2026-11-27.** On the Entra ID Free tenant (no P1 or P2, no trial),
the diagnostic setting accepted both `AuditLogs` and
`ServicePrincipalSignInLogs`. `AuditLogs` got 6 rows and
`AADServicePrincipalSignInLogs` 1, about 10 to 15 minutes after each event.
**D1 stands:** no trial, and S4 can get a sign-in rule. Details, and the two
surprises (`ClientCredentialType` is `clientAssertion` for a certificate
sign-in; a key's add and delete log the same operation name), are in
`docs/FINDINGS.md`, "M4 log path check". The text below is the plan as it was.

**Before any strike code is written and before any trial is activated**, check
on the free tenant whether these two Entra log categories reach a Log Analytics
workspace through a diagnostic setting:

- **`AuditLogs`**, which the four directory rules read;
- **`ServicePrincipalSignInLogs`** (table `AADServicePrincipalSignInLogs`), which
  a sign-in rule for S4 would read.

**What Microsoft says about the licence.** The current page, "Integrate
Microsoft Entra logs with Azure Monitor logs" (updated 2026-06-15), lists the
prerequisites under "To use this feature, you need:":

- an Azure subscription;
- "At least the Security Administrator role in the Microsoft Entra tenant";
- a Log Analytics workspace;
- "Permission to access data in a Log Analytics workspace".

It names **no Entra licence**, and nor does the diagnostic settings page (updated
2026-02-26). Older guidance said otherwise: the CIS Microsoft Azure Foundations
benchmark quotes "To export sign-in data, your organization needs an Azure AD P1
or P2 license". Community threads also report that on Entra ID Free only
`AuditLogs` arrived. The documentation and the reports disagree, which is why
this step is a live check and not an assumption.

The check uses no strike code and no trial, and the tool makes no write. It is
its own session, with its own lab build and teardown. The runbook is
`docs/runbooks/m4-log-path-check.md`, and you run every command in it:

1. Rebuild the lab, with a new suffix.
2. Create a throwaway workspace `law-fns-logcheck` in `rg-fns-logcheck`, and a
   tenant-level Entra diagnostic setting `fns-logcheck` that sends `AuditLogs` and
   `ServicePrincipalSignInLogs` to it. **Stop rule:** if the API refuses, record
   the exact response, retry with `AuditLogs` alone, then clean up and report.
3. Cause **one** harmless audit event: a certificate valid for at most a day on
   the read-only `sp-fns-scout`.
4. Cause **one** service principal sign-in: the scout signs in with that
   certificate, in a temporary CLI profile.
5. Delete the certificate. Run the KQL, polling for up to 2 hours, and paste the
   results. The queries return no IDs or user names.
6. Delete the setting and the workspace, then `lab-down`.

**Results:**

- **Both tables fill:** D1 stands. No trial; S4 can get a sign-in rule. FINDINGS
  records that both categories export on Entra ID Free, with the date.
- **`AuditLogs` fills, sign-ins don't, or either is refused:** **stop**. No
  strike code is written until you choose one of these:
  - **a.** Continue without sign-in logs. The 10 existing rules need only
    `AuditLogs`, so the strikes and their detection results still work. S4's
    sign-in gets no rule, and its detection result says "sign-in logs not
    available on Entra ID Free".
  - **b.** The Entra ID P2 trial: free, 30 days, one per tenant. Activation can
    need a payment method or can fail on this kind of tenant (see the costs
    below). Start it only for sessions C and D, which then have to fit inside
    the 30 days.
  - **c.** One paid Entra ID P1 licence for one month (list price about $6 a
    user a month; check it on the day). It is cheaper than P2, and P1 is
    enough for log export. Check whether your subscription's credit can pay for
    it: Azure credits usually don't cover Microsoft 365 or Entra licences.
  - **d.** Stop M4's detection half; do record, harden and prove the fix only.
- **Neither table fills:** stop as above, with the same options. Option a then
  loses the four directory rules too.

Cost: one workspace on the 5 GB/month free tier, for a few hours.

## Sessions

Four live sessions after step 1, each with its own runbook section and its own
report back.
The lab can stay up between them: the scope renews with
`"-replace=time_offset.scope_expiry"`, and every certificate lives for 1 day at
most.

| Session | Needs | Strikes? | Time (rough) |
| --- | --- | --- | --- |
| 1. Log path check (`docs/runbooks/m4-log-path-check.md`) | a lab build and a throwaway workspace, both removed at the end | no | **done 2026-11-27: passed** |
| A. Rebuild, baseline scout, the `Directory.Read.All` and custom-role tests | step 1 reported; a fresh build | no | 1.5 h |
| B. Logging on, legitimate use, record | A; the workspace and the Sentinel trial | no | 1 h, plus up to a day for logs to settle |
| C. Strikes and detection results | B; step 1 passed or you chose an option; `fns strike` built from the approved strike plan | **yes**: S1 to S4 | 2 h, mostly waiting for alerts |
| D. Harden, apply, prove the fix, and the required denials (D6) | C | **attempts that must be denied**: D-1 to D-5 | 1.5 h |
| Teardown | everything recorded and committed | | 15 min |

### Session A: rebuild the lab

The lab was destroyed, so this is a fresh M1 build (`docs/runbooks/m1-live-run.md`,
steps 2 to 4). It gets a **new random suffix**: `random_string.suffix` went with
the old state. The `tiin02` names in the fixtures stay valid as recordings of
endpoints that no longer exist.

1. **You:** `az login --tenant <TENANT_ID>`, `az account set --subscription
   <SUBSCRIPTION_ID>`, and check the table shows the lab tenant and your account.
2. **You:** keep `lab/terraform.tfvars` (it holds IDs only) or rewrite it with
   M1 step 3. Leave `scout_directory_read_all` unset (the default is `true`).
3. **You:** `uv run poe lab-check`, then `uv run poe lab-up`. Review the plan:
   only additions, nothing to change or destroy. The M4 runbook gives the
   expected count, worked out from the `.tf` files (M1 had 34; M2 added a Graph
   grant). A plan with a different count is a stop. Type `yes`.
4. **You:** `uv run fns scope check scope.lab.yaml`: lab tenant, subscription,
   `rg-fns-lab`, 17 scout and 6 prove operations, expiry 7 days out. Then wait
   about 10 minutes for the Graph grants to show up in tokens.
5. **You:** scout once as yourself and once as `sp-fns-scout` (M1 steps 5 to 8,
   with a 1-day certificate). Record the scout run as `fixtures/lab-run-4`.
   Both digests must match.
6. **Me:** a PR with `fixtures/lab-run-4` (sanitized, the no-real-IDs test,
   a golden digest, the new contract rendered by `lab/contract.tf` with the new
   suffix), after you send the report.

### Session A, continued: can the scout drop `Directory.Read.All`?

Today's evidence (FINDINGS, "Is `Directory.Read.All` needed?"): the full set is
**sufficient**, and nobody has tested whether it is **minimal**. The old plan
compared digests before and after the change. That doesn't work: the snapshot
contains the scout's own Graph grants, so removing one changes the digest
whatever else happens. The comparison has to be on the **same lab state**:

1. **You:** in `lab/terraform.tfvars`, set `scout_directory_read_all = false`,
   then `uv run poe lab-up`. The plan must show **1 to destroy** (the scout's
   `Directory.Read.All` assignment) and nothing else.
2. Wait about 10 minutes.
3. **You:** scout as **yourself** (the reference for this lab state), then as
   `sp-fns-scout` with a fresh 1-day certificate. Don't record either.
4. **Pass:** both digests are equal, every collector is `complete`, and there is
   no `http-403`. Then `Directory.Read.All` leaves the default; that is my PR,
   with a FINDINGS entry and a DECISIONS row. **Fail:** any 403, `partial`, or
   different owner, member or SKU counts. Then it stays, and FINDINGS records
   which call needed it.
5. This also answers the open question "is `LicenseAssignment.Read.All` alone
   enough for `/subscribedSkus`?". It is the only grant left that covers it.
6. **You:** set it back to `true` and apply (1 to add), so the later sessions
   run on the known set. Or keep `false` if step 4 passed.

The lab makes this a weak test: its owners are one user and three service
principals, and no service principal is in a group, so `memberOf` returns
nothing either way. D3 adds a lab group with `sp-billing-agent` as a member, so
`/servicePrincipals/{id}/memberOf` has something to lose.

### Session A, continued: narrow the scout from Reader to a custom role

The scout's ARM side is **Reader on the subscription** (`*/read`). The collector
uses 7 ARM read operations, the `arm:` lines of `scope.lab.yaml`:

- `Microsoft.Authorization/roleAssignments/read`
- `Microsoft.Authorization/roleDefinitions/read`
- `Microsoft.Authorization/denyAssignments/read`
- `Microsoft.Authorization/roleEligibilitySchedules/read`
- `Microsoft.Resources/subscriptions/resourceGroups/resources/read`
- `Microsoft.KeyVault/vaults/read`
- `Microsoft.Storage/storageAccounts/read`

**Me (offline, before the session):** a `scout_custom_role` variable, default
`false`. When it is `true`, `lab/` creates an `azurerm_role_definition`
"Fang & Scale scout (read)" with exactly those actions, assignable at the lab
subscription, and assigns it to the scout instead of Reader. A test keeps the
role's actions equal to the scope file's `arm:` operations, the same way
`tests/test_lab.py` keeps the scope in step with the collector.

**You (in session A, one change at a time):**

1. Set `scout_custom_role = true` and apply. The plan: 1 role definition and 1
   assignment to add, the Reader assignment to destroy. Wait 10 minutes; custom
   roles take a while to apply.
2. Scout as yourself and as `sp-fns-scout`, on the same state. The pass and fail
   rules are as above.
3. **Pass:** the custom role becomes the documented scout permission set (README,
   "Scout permissions"), as a variable you can choose. **Fail:** the 403 names
   the missing action. I add it if it is read-only, and FINDINGS records the
   undocumented action.

Unknown until it runs: whether `.../resourceGroups/resources/read` is the action
ARM checks for the RG resource listing. It is the documented one, and a 403
would say otherwise. Separate from this: H1, harden proposing a narrower custom
role *for the agent*, stays on the roadmap after v0.1.

### Session B: logging on, legitimate use, record

**Me (offline, before the session):** `lab/monitoring.tf`, behind
`enable_monitoring` (default `false`, so the M1 to M3 lab is unchanged).
**Built 2026-11-27** (`lab/README.md`, "Monitoring"): 18 more resources when on,
validated with `lab-check` only:

| Resource | Feeds | Detection rules that read it |
| --- | --- | --- |
| Log Analytics workspace, PerGB2018, 30-day retention | everything below | |
| Sentinel onboarding on that workspace | the alert rules | |
| Subscription diagnostic setting: Activity Log (Administrative, Security, Policy) | `AzureActivity` | listKeys, RBAC assignment, vault control-plane write, run code on the identity host |
| Key Vault diagnostic setting: `AuditEvent` | `AzureDiagnostics` | secret access |
| Blob service diagnostic settings on both accounts: StorageRead, StorageWrite | `StorageBlobLogs` | blob access or shared key |
| Entra diagnostic setting: `AuditLogs` and `ServicePrincipalSignInLogs` (step 1 showed both arrive on Entra ID Free) | `AuditLogs` | credential added, owner added, app role assignment, directory role assigned |
| The 11 rules from `detections/` (10, plus the S4 sign-in rule added after step 1), rendered by `fns detections export` | Sentinel scheduled rules | |

Tests (offline): every table a rule names has a diagnostic setting that feeds
it; the rules deployed are exactly the files in `detections/`; nothing in it
deploys when `enable_monitoring = false`.

**You:**

1. Set `enable_monitoring = true` and apply. The Entra diagnostic setting needs
   Global Administrator or Security Administrator: you are the former.
2. Open the workspace in the Defender portal (Sentinel moved there; the Azure
   portal experience retires on 2027-03-31). Check that **Free trial** shows 31
   days.
3. **Legitimate use, as the agent (by hand).** This is the "functional test as
   the workload's identity" that record mode harvests (PLAN §5). With a 1-day
   certificate on `sp-billing-agent` (the M3 runbook, step 5 and its cautions):
   one `az storage blob download` and one `az storage blob upload` on
   `stinvoices<suffix>/invoices`, with `--auth-mode login`. Then delete the
   certificate.
   - The upload is a write, and you make it by hand, not the tool. Rule 1 is
     about the tool.
4. Wait for the rows: Activity Log within minutes, Storage and Key Vault within
   about 15 minutes, Entra audit logs up to an hour or so. Then export the agent's
   rows from each table as JSON (the queries go in the runbook).
5. **You:** `uv run fns record <exported files> --identity <agent object id>
   --contract <rendered contract> --out <file>`. Send the output and the
   `unmapped` list.

**Me:** a log sanitizer (object IDs, resource IDs, caller IPs, UPNs, correlation
IDs mapped to placeholders, as the scout sanitizer does) and
`fixtures/lab-run-4/logs/`, so record mode has a real-log regression test next
to the hand-written ones in `tests/harden/data/`.

### Session C: strikes and detection results

The strikes, every request they send, in order, and every undo are in
`docs/milestones/M4-strikes-plan.md` (D4: a plan only, with its own decisions
SD1 to SD5). The summary below is kept short on purpose; the strike plan is the
reference.

| Strike | Write (as `sp-billing-agent`) | Cleanup | Rule that should fire | Table |
| --- | --- | --- | --- | --- |
| listKeys | `POST .../storageAccounts/stpayroll<suffix>/listKeys` | none (reads keys, changes nothing) | `storage-listkeys-by-workload` | `AzureActivity` |
| vault write | a tag on `kv-crown-<suffix>` through `vaults/write` | remove the tag | `keyvault-control-plane-write-by-workload` | `AzureActivity` |
| owner adds credential | a password, valid for 1 hour, on `app-escalation-target` | delete it | `app-credential-added-by-workload` | `AuditLogs` |
| app role self-grant | the escalated identity grants the agent a marker role that grants nothing, on a lab app; never a directory role (strike plan, S4 and SD2) | delete it, disable and remove the role | `app-role-assignment-by-workload` | `AuditLogs` |

**You:** review the strike plan the tool prints, approve its hash, run it (one
agent certificate for the session), then delete the certificate.

**Detection result per strike:** fired or not, alert time minus strike time, and
the rows that matched. A strike observed at rung 3 with no alert is a
`detection-gap` finding (PLAN §4). Allow up to 2 hours for audit-log rules.
Sentinel's shortest scheduled frequency is 5 minutes, but the logs arrive later
than that. How the result gets read is D5.

### Session D: harden, apply, prove the fix

1. **You:** scout as `sp-fns-scout` and `fns contain` on the recorded contract
   (from session B).
2. **You:** `uv run fns harden --contract <recorded> --snapshot <snap> --out
   harden.diff`. Send the proposal and its `plan sha256:`. I expect the two
   grants above. Anything else is a FINDINGS entry before we go on.
3. **You:** `git apply harden.diff`, then `uv run poe lab-up`. The plan must
   show exactly the proposal's removals. `harden --apply` stays unbuilt: you
   apply the diff, the tool does not.
4. **You:** a fresh scout and contain: the model says 0 critical reachable.
5. **You:** `fns prove --live` as the agent (the M3 runbook, steps 5 to 8),
   recorded as `fixtures/lab-run-5`.
   - **Expected:** the Key Vault and payroll reads are observed denied with no
     path left, so they **pass**, at rung 3, `verified`. The invoices read is
     observed allowed, so it **passes**.
   - **D6 (approved):** the post-harden attempts D-1 to D-5 from the strike plan
     must all be denied. Those denials are the observed evidence for the
     application items. `directory:tenant roleAssignments/write` gets no direct
     attempt, since that would be a directory role assignment. It is SD3 in the
     strike plan.
6. **Me:** the `lab-run-5` PR: before-and-after verdicts, the observed result,
   FINDINGS, and the prove golden.

### Teardown

**You:** `uv run poe lab-down` once every fixture is committed. It also removes
the workspace, the Sentinel onboarding, the diagnostic settings and the rules.
The Entra diagnostic setting is tenant-level: check it is gone
(`az rest --method get --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"`).
Then end any trial you started (step 1, option b) before it converts or
expires.

## Trials, cost and expiry against the $100 credit

Prices are in USD, from Microsoft's pages as of 2026-11-26. Check them in the
Azure pricing calculator for your region on the day.

| Item | Needed for | Cost | Expiry and limits |
| --- | --- | --- | --- |
| The lab (1 Key Vault, 2 LRS storage accounts) | every session | cents per day | until `lab-down` |
| Log Analytics workspace | session B on | pay-as-you-go Analytics logs: the first 5 GB a month per billing account are free, then roughly $2 to $3 per GB (one Q&A cites $2.30 for East US). 31 days of retention included, 90 with Sentinel. Queries are free | none; it bills until deleted |
| Activity Log into Log Analytics | 4 rules | free to ingest, as far as I know; **verify** on the Azure Monitor pricing page | |
| Microsoft Sentinel | the 11 rules and alerts | **31-day free trial** from enabling it on the workspace: Log Analytics ingestion and Sentinel analysis are waived up to 10 GB a day. Automation and data lake charges still apply (we use neither). After the trial, Sentinel's per-GB price on top of Log Analytics | 31 days; at most 20 trial workspaces per tenant |
| Entra ID P2 trial | only if step 1 fails and you choose option b | free | **30 days, one trial per tenant.** Community reports say activation can need a payment method, or can fail on tenants created from a personal Microsoft account. Unverified until you try |
| Key Vault operations, storage transactions | probes, strikes, legitimate use | well under $1 | |

**Expected total for M4: under $5**, if the sessions fit in the 31-day Sentinel
trial and the lab is torn down at the end. A lab this size logs megabytes a day.
The 10 GB/day trial cap and the 5 GB/month free tier are both orders of magnitude
above that. **The real risk is forgetting `lab-down`:** after the trial, a
Sentinel workspace bills per GB for as long as it exists. A **$10 budget alert**
(D7, `lab/budget.tf`) turns that into an email. **Azure for Students is not
supported** by Cost Management (Microsoft's offer list), so it can't have a
budget. `lab/README.md`, "Cost alert", has the offer check and what to do
instead.

Timing:

- Start Sentinel (session B) only when sessions C and D can follow within the
  same 31 days.
- Start the P2 trial (only if step 1 fails and you choose option b) last, and
  only for the run that needs it. A P2
  licence changes the tenant: `/subscribedSkus` is no longer empty, and the PIM
  surface becomes `collected` instead of `not-applicable` with evidence. Do the
  prove-the-fix run either entirely before the trial starts or entirely inside it.
  If the trial expires halfway, the PIM surface is `not collected` and every
  finding is `inconclusive`.

## Who does what

| You (by hand, in the tenant or the portal) | Me (offline, through PRs) |
| --- | --- |
| `az login`; review and approve every `terraform apply` and `destroy` | `lab/monitoring.tf`, the custom scout role, the lab group (D3), with offline tests |
| The log path check (step 1), any trial you choose, `budget_alert_email` in `terraform.tfvars`, open Sentinel in the Defender portal | The detection deployment (D2) and its tests |
| Create and delete every certificate (scout, agent), with the list checks | `docs/runbooks/m4-live-run.md`: exact commands, the expected plan for every apply, stop rules, emergency cleanup |
| Legitimate use as the agent (one download, one upload) | The log sanitizer, and `fns record` regression tests on the real logs |
| Run `fns scout`, `record`, `contain`, `harden`, `prove --live`, `strike` | The `fns strike` plan (D4), then its code with negative gate tests, after you approve it |
| Approve every strike plan hash; apply the harden diff | Fixtures `lab-run-4` and `lab-run-5`, goldens, FINDINGS, DECISIONS, STATUS |
| Read alerts (D5), send each report back | Reading the reports, and stopping you if anything deviates from the expected plan |
| `lab-down`, and end the trials | The `m4` tag, after your review |

I make no Azure, Graph or Log Analytics call myself, and I never hold a lab
credential. As in M3, every live command is yours.

## Not in this plan

- `harden --apply`: you apply the diff by hand (D4 covers strikes only).
- H1 narrowing for the agent (a custom role instead of removal): on the roadmap
  after v0.1.
- Strikes beyond the four (M6).

## Decisions (approved 2026-11-26)

| | Decision | Outcome |
| --- | --- | --- |
| D1 | Entra P2 trial | **Approved, changed:** no trial up front. Step 1, the log path check, comes first. If `AuditLogs` or `ServicePrincipalSignInLogs` don't arrive on Entra ID Free, stop, and you choose from options a to d |
| D2 | Deploying the rules | **Approved:** Terraform `lab/monitoring.tf` reads `fns detections export` output; `lab-down` removes it |
| D3 | Lab group for the `memberOf` test | **Approved:** `grp-fns-billing`, with `sp-billing-agent` as a member and no roles |
| D4 | `fns strike` | **Approved as a plan only:** `docs/milestones/M4-strikes-plan.md`. No strike code until that plan and its SD1 to SD5 are approved. Your conditions: stop at the last reversible step (prove the agent can write role assignments, never assign a directory role); a tested undo, credentials of 1 day at most, a journal entry, a post-cleanup check and an emergency runbook section for every strike; lab-created objects only, enforced by the gate with fuzz tests; every Graph write listed in order with its undo |
| D5 | Reading detection results | **Approved:** you run one KQL query per strike and paste the result |
| D6 | Items after harden | **Approved:** re-run the Graph strikes after harden and require an observed denial (strike plan, D-1 to D-5) |
| D7 | $10 budget alert | **Approved:** `lab/budget.tf` (`azurerm_consumption_budget_subscription`), with the address from `terraform.tfvars`. Not possible on Azure for Students (`lab/README.md`) |
| D8 | Keep both scout variables | **Approved:** `scout_directory_read_all` and `scout_custom_role` stay variables, with the defaults moved to whatever passed |

## Sources

- Microsoft Sentinel billing (31-day trial, 10 GB/day, 20 workspaces per
  tenant): <https://learn.microsoft.com/azure/sentinel/billing>
- Sentinel in the Azure portal retires 2027-03-31; new workspaces onboard to the
  Defender portal: <https://learn.microsoft.com/azure/sentinel/overview>
- Entra logs to Log Analytics. Its current prerequisites (updated 2026-06-15)
  list a subscription, Security Administrator and a workspace, and no licence:
  <https://learn.microsoft.com/entra/identity/monitoring-health/howto-integrate-activity-logs-with-azure-monitor-logs>.
  The diagnostic settings page (updated 2026-02-26):
  <https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings>
- The older P1/P2 statement for sign-in export, as the CIS benchmark quotes it:
  <https://www.tenable.com/audits/items/CIS_Microsoft_Azure_Foundations_v6.0.0_L2.audit:535829e8158127119f7f757811cc0ce8>
- Offers Cost Management does not support (Azure for Students):
  <https://learn.microsoft.com/azure/cost-management-billing/costs/understand-cost-mgt-data>
- Log Analytics pricing (5 GB/month free per billing account):
  <https://azure.microsoft.com/pricing/details/monitor/>
- Entra ID P2 trial activation reports (community, not official):
  <https://learn.microsoft.com/en-us/answers/questions/1464265/i-cant-activate-the-trial-of-microsoft-entra-id-p2>
