# Lab (Terraform)

Builds the M1 lab from `docs/PLAN.md` section 7 in a **dedicated lab tenant**.
Never point it at a production tenant: it creates identities that are
over-privileged on purpose.

| Object | Purpose |
| --- | --- |
| `rg-<prefix>-lab` | Everything below lives here; it is the only RG in `scope.lab.yaml` |
| `sp-billing-agent` | Assumed compromised: Contributor on the RG, Graph `Application.ReadWrite.OwnedBy`, owner of `app-escalation-target`, Blob Data Contributor on invoices (legitimate use) |
| `app-escalation-target` | App + SP with Graph `AppRoleAssignment.ReadWrite.All`, owned by the agent |
| `kv-crown-<suffix>` | Key Vault (RBAC mode) with one synthetic secret |
| `stpayroll<suffix>` | Storage with a synthetic payroll blob; shared keys on, so `listKeys` is a real path |
| `stinvoices<suffix>` | Storage the agent legitimately uses |
| `id-verifier` | Reader on the RG; used only by `fns prove` (M3) |
| `sp-fns-scout` | Read-only scout: Reader on the subscription + Graph read permissions (see the root README) |

Not in the lab: a deny assignment. Deny assignments cannot be created directly;
the bundled demo fixture covers them. Logging and the detection rules are in the
lab but off by default (`enable_monitoring`, below).

No client secrets or certificates are created. State is local
(`lab/terraform.tfstate`, gitignored) and contains the synthetic secret and the lab's
object IDs: never commit it.

```
copy lab\terraform.tfvars.example lab\terraform.tfvars   # then edit
uv run poe lab-check   # fmt + validate, no credentials
uv run poe lab-up      # init + apply (you approve the plan)
uv run poe lab-down    # destroy
```

`lab-up` also writes `../scope.lab.yaml`, which expires after `scope_valid_days`
(default 7). Refresh it with
`terraform -chdir=lab apply -replace=time_offset.scope_expiry`.

## Cost alert (M4, decision D7)

`budget.tf` adds a monthly budget on the lab subscription, emailing at 50% and
100% of actual spend and at 100% of forecast. It exists only when
`budget_alert_email` is set in `terraform.tfvars` (gitignored; the address never
goes in a committed file). `budget_amount` defaults to 10. `lab-down` destroys
the budget with everything else.

**First check your subscription's offer.** Microsoft lists **Azure for Students**
(`MS-AZR-0170P`, quota ID `AzureForStudents_2018-01-01`) and Azure for Students
Starter among the offers Cost Management does **not** support
(<https://learn.microsoft.com/azure/cost-management-billing/costs/understand-cost-mgt-data>).
On those, a budget can't be created, in Terraform or in the portal.

```powershell
$sub = az account show --query id -o tsv
az rest --method get --url "https://management.azure.com/subscriptions/${sub}?api-version=2022-12-01" --query subscriptionPolicies.quotaId -o tsv
```

The portal shows the same: **Subscriptions → your subscription → Overview →
Offer / Offer ID**.

- **A supported offer** (free account, pay-as-you-go, and so on): set
  `budget_alert_email` and apply. Or create it by hand: **Cost Management +
  Billing → Cost Management → Budgets → + Add**:
  - scope: the lab subscription; name `budget-fns-lab`;
  - reset period **Monthly**; amount **10**;
  - alert conditions **Actual 50%**, **Actual 100%**, **Forecasted 100%**;
  - your address under alert recipients, then **Create**.

  A new subscription can take up to 48 hours before budgets are available.
- **Azure for Students:** leave `budget_alert_email` empty. A plan with the
  budget would fail on that resource alone. Students credit has a spending
  limit: when it runs out, resources stop instead of billing a card. Watch what
  is left in the portal's **Education** hub (search "Education") before and
  after each M4 session. The cost that matters in M4 is Log Analytics and
  Sentinel ingestion, so its monitoring can also alert on ingested volume
  (M4 plan).

## Monitoring (M4, decision D2)

`monitoring.tf` adds logging and the detection rules for M4 sessions B to D. It
exists only when `enable_monitoring = true` in `terraform.tfvars`; with the
default `false`, the lab is the M1 to M3 lab. `lab-down` removes all of it.

| Resource | Feeds |
| --- | --- |
| `law-<prefix>-<suffix>`, PerGB2018, 30-day retention, daily cap `monitoring_daily_quota_gb` (1 GB) | everything below |
| Sentinel onboarding on that workspace (starts the 31-day trial) | the alert rules |
| Subscription Activity Log: Administrative, Security, Policy | `AzureActivity` |
| Key Vault `AuditEvent`, into `AzureDiagnostics` | `AzureDiagnostics` |
| Blob service of both accounts: StorageRead, StorageWrite | `StorageBlobLogs` |
| Entra (tenant-level): AuditLogs, ServicePrincipalSignInLogs | `AuditLogs`, `AADServicePrincipalSignInLogs` |
| One Sentinel scheduled rule per file in `detections/` | alerts |

With monitoring on, the plan adds **18** more resources: 7 for the workspace and
its feeds, and 11 rules.

- **The rules** come from `detections.json`, generated from `detections/` by
  `uv run fns detections export --terraform lab/detections.json`. A test fails if
  the file is out of date. Terraform fills `{{monitored_identities}}` at apply time
  with `sp-billing-agent` and `app-escalation-target`, each by object ID and by
  client ID.
- **The Entra setting is tenant-level.** If a destroy fails halfway, it can
  outlive the lab. Check after `lab-down`:
  `az rest --method get --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"`.
- **Both Entra categories work on Entra ID Free.** The log path check showed it
  on 2026-11-27 (`docs/FINDINGS.md`).
