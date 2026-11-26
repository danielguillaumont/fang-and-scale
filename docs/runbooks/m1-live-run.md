# M1 Phase B live run

Run the Terraform lab and `fns scout` against a real tenant for the first time,
then tear it down. Everything here is done by a person; the tool never applies
Terraform or creates credentials on its own.

All commands are Windows PowerShell, run from the repository root.

> Use a **dedicated lab tenant**. The lab creates identities that are
> over-privileged on purpose (one of them can grant itself any Graph permission).
> Never run this against a tenant that holds anything you care about.

## Identities and permissions at a glance

What `uv run poe lab-up` (step 4) grants. Nothing else is granted.

| Identity | Azure RBAC | Microsoft Graph (application permissions) | Other |
| --- | --- | --- | --- |
| `sp-billing-agent` (assumed compromised) | **Contributor** on `rg-fns-lab`; **Storage Blob Data Contributor** on `stinvoices<suffix>` | **Application.ReadWrite.OwnedBy** | Owner of the `app-escalation-target` application |
| `app-escalation-target` | none | **AppRoleAssignment.ReadWrite.All** | Owned by you and `sp-billing-agent` |
| `id-verifier` (used by `fns prove` in M3) | **Reader** on `rg-fns-lab` | none | |
| `sp-fns-scout` (the identity `fns scout` runs as) | **Reader** on the lab subscription | **Application.Read.All**, **RoleManagement.Read.Directory**, **Directory.Read.All** | Optional GitHub OIDC federated credential (off by default) |
| You (the account running `lab-up`) | **Key Vault Secrets Officer** on `kv-crown-<suffix>`; **Storage Blob Data Contributor** on both storage accounts | none | Owner of all four applications and service principals |

Why the scout set is what it is, and what it can and cannot do: see the root
`README.md`, "Scout permissions". Short version: Reader is `*/read` only (no
`listKeys`, no data plane), and every Graph permission is read-only.
`Directory.Read.All` is the broadest; step 9 decides whether it can be dropped.

The intended blast-radius paths the lab exists to expose:

- `sp-billing-agent` → Contributor on the RG → `listKeys` on `stpayroll<suffix>`
  (shared keys are enabled on purpose) → payroll blobs.
- `sp-billing-agent` → Contributor → can switch `kv-crown-<suffix>` out of RBAC
  mode and grant itself secret access.
- `sp-billing-agent` → owns `app-escalation-target` → can add a credential to it →
  acts with `AppRoleAssignment.ReadWrite.All` → can grant itself any Graph
  permission.
- Legitimate use that must keep working: blob read/write on `stinvoices<suffix>`.

## 1. Account and tenant (portal)

1. Create a new Microsoft account and an Azure free account at
   <https://azure.microsoft.com/free>. The new account gets its own tenant
   ("Default Directory") and a subscription. Use it only for this lab.
2. In the Azure portal, note:
   - **Tenant ID**: Microsoft Entra ID → Overview.
   - **Subscription ID**: Subscriptions.
3. Confirm your roles (both are the default for the account that created them):
   - **Global Administrator**: Entra ID → Roles and administrators → Global
     Administrator → Assignments. Needed to grant Graph application permissions.
   - **Owner** on the subscription: Subscriptions → your subscription → Access
     control (IAM) → Role assignments. Needed to create RBAC role assignments.

Creates: a tenant and a subscription (free credit; the lab itself costs cents per
day: one Key Vault, two LRS storage accounts).

## 2. Tools and sign-in

```powershell
winget install -e --id Microsoft.AzureCLI      # then open a new terminal
terraform version                              # needs 1.9 or later
az login --tenant <TENANT_ID>
az account set --subscription <SUBSCRIPTION_ID>
az account show --query "{tenant:tenantId, sub:id, user:user.name}" -o table
az provider register --namespace Microsoft.KeyVault --wait
az provider register --namespace Microsoft.Storage --wait
```

Check that the table shows the lab tenant, the lab subscription and your lab
account before going on.

Creates: an Azure CLI session in `%USERPROFILE%\.azure`; registers the Key Vault
and Storage resource providers on the subscription.

## 3. Terraform variables

`location` is required and has no default. Subscriptions can restrict regions by
policy: Azure for Students, for example, assigns "Allowed resource deployment
regions" and blocks `eastus`. List what your subscription allows and pick one:

```powershell
az policy assignment list --query "[].{name:displayName, allowed:parameters.listOfAllowedLocations.value}"
```

An empty result or a null `allowed` means no region policy. Then write the file:

```powershell
$tenant = az account show --query tenantId -o tsv
$sub = az account show --query id -o tsv
$location = "canadacentral"                     # one of the allowed regions
$tfvars = @"
tenant_id         = "$tenant"
subscription_id   = "$sub"
location          = "$location"
prefix            = "fns"
github_repository = ""
"@
[IO.File]::WriteAllText("$PWD\lab\terraform.tfvars", $tfvars)   # UTF-8 without BOM
Get-Content lab\terraform.tfvars
```

Creates: `lab/terraform.tfvars` (gitignored). It holds IDs, not secrets.

## 4. Build the lab (you approve the apply)

```powershell
uv run poe lab-check                    # fmt + validate, no credentials used
uv run poe lab-up                       # terraform init + apply; review the plan, then type yes
uv run fns scope check scope.lab.yaml
```

Review the plan before typing `yes`: it should show **34 resources to add**,
nothing to change or destroy. Apply takes a few minutes (it waits 90 s for RBAC to
propagate before seeding data). It aborts before creating anything if azurerm or
azuread is signed in to a tenant other than `tenant_id`.

Creates (in Azure and Entra):

- Resource group `rg-fns-lab` (tags `project=fang-and-scale`, `purpose=lab`).
- Applications and service principals: `sp-billing-agent`,
  `app-escalation-target`, `id-verifier`, `sp-fns-scout`. No secrets or
  certificates.
- Five Graph app role assignments and seven RBAC role assignments, exactly as
  in the table above.
- Key Vault `kv-crown-<suffix>` (RBAC mode, soft delete 7 days, no purge
  protection) with the synthetic secret `payroll-db-password`.
- Storage `stpayroll<suffix>` (container `payroll`, blob
  `employees-SYNTHETIC.csv`) and `stinvoices<suffix>` (container `invoices`, blob
  `invoice-0001-SYNTHETIC.json`).

Creates locally:

- `lab/terraform.tfstate`: gitignored; it contains the synthetic secret.
- `scope.lab.yaml`: gitignored; real lab IDs, the 12 read operations, budget 500
  calls / 15 minutes, expires 7 days after creation. To renew it:
  `terraform -chdir=lab apply "-replace=time_offset.scope_expiry"`.

`fns scope check` should print the lab tenant, subscription, `rg-fns-lab`, 12
scout operations and the expiry.

Then **wait about 10 minutes**: new Graph app role grants take a while to show up
in tokens.

### Troubleshooting step 4

- **Policy error `RequestDisallowedByPolicy` on the resource group**: the region
  is not allowed. Change `location` in `lab/terraform.tfvars` (step 3) and run
  `uv run poe lab-up` again.
- **Key Vault create fails with a 404 while Terraform polls, but the vault
  exists** (seen in `canadacentral`, `docs/FINDINGS.md`): the vault was created,
  but it is not in the Terraform state. Import it, then apply again:

  ```powershell
  $sub = az account show --query id -o tsv
  $kv = az keyvault list -g rg-fns-lab --query "[0].name" -o tsv
  terraform -chdir=lab import azurerm_key_vault.crown_jewels "/subscriptions/$sub/resourceGroups/rg-fns-lab/providers/Microsoft.KeyVault/vaults/$kv"
  uv run poe lab-up                     # creates the rest; review, then type yes
  ```

  Do not delete the vault by hand: soft delete keeps the name reserved for 7 days.

## 5. Sign in as the read-only scout

This is what proves the documented permission set. It creates a certificate
credential on `sp-fns-scout` that expires in 2 days; step 8 deletes it.

```powershell
$tenant = az account show --query tenantId -o tsv          # still signed in as you
$appId = (terraform -chdir=lab output -json scout | ConvertFrom-Json).client_id
$end = (Get-Date).AddDays(2).ToString("yyyy-MM-dd")
$cred = az ad app credential reset --id $appId --create-cert --end-date $end --append | ConvertFrom-Json
$cred.fileWithCertAndPrivateKey                             # path of the PEM (private key)
az login --service-principal --username $appId --certificate $cred.fileWithCertAndPrivateKey --tenant $tenant
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table
```

The last command should show `type` = `servicePrincipal` and `user` = the scout's
client ID.

A new certificate takes a few minutes to become usable. If the login fails with
`AADSTS700027` (client assertion contains an invalid signature), the credential
has not propagated yet: wait 3 minutes and run the `az login --service-principal`
line again. Do not create another certificate; that restarts the wait.

Creates: a certificate credential on the `sp-fns-scout` application and a PEM file
with its private key in your user profile. Keep it out of the repo (`*.pem` is
gitignored anyway).

Quicker alternative: skip this step and scout as yourself. It works, because the
tool is read-only either way, but it does not test the scout permission set.

## 6. Scout twice (the M1 gate)

```powershell
uv run fns scout --scope scope.lab.yaml --record fixtures/lab-run-1
uv run fns scout --scope scope.lab.yaml
```

Compare the `digest sha256:` line of the two runs. They must be identical (M1
exit gate), as long as nothing in the tenant changed in between.

Exit codes: `0` OK; `1` bad or expired scope file, or a sign-in problem; `4`
tenant mismatch (nothing was called).

Creates locally:

- `.fns/journal.sqlite`: every gate decision and call result (gitignored).
- `.fns/snapshots/<digest>.LIVE.json`: the snapshots, with real IDs (gitignored).
- `fixtures/lab-run-1/`: `manifest.json`, `exchanges.json`, `scope.yaml`
  (sanitized), and `_idmap.json` (real-to-placeholder mapping, gitignored,
  never commit).

Makes in Azure: only GET requests, about 30 to 60 per run, all within the scope
budget.

## 7. Check the recorded fixture (do not commit yet)

```powershell
uv run pytest tests/fixtures/test_no_real_ids.py -q
uv run fns demo scout --fixture fixtures/lab-run-1
```

The test must pass: no non-placeholder GUIDs, real emails, tenant domains, tokens
or secrets in the fixture. The replay prints every line with `FIXTURE`. Also skim
`fixtures/lab-run-1/exchanges.json` for anything personal the sanitizer missed.

Creates: `.fns/snapshots/<digest>.FIXTURE.json`.

## 8. Remove the scout certificate

```powershell
az login --tenant $tenant                                   # back to your own account
az ad app credential list --id $appId --cert --query "[].{keyId:keyId, end:endDateTime}" -o table
az ad app credential delete --id $appId --key-id <keyId> --cert
Remove-Item $cred.fileWithCertAndPrivateKey
az ad app credential list --id $appId --cert -o table      # should be empty
```

Removes: the certificate credential from `sp-fns-scout` and the local PEM file.

## 9. Report back

First run (2026-11-26): done. Results are in `docs/FINDINGS.md`; the recorded
set is committed as `fixtures/lab-run-1`. For later runs:

Send:

- both digests from step 6;
- the Collectors table from step 6, especially any `failed`, `partial`,
  `skipped` or `http-403` rows;
- the result of the step 7 test.

### Next live run: can `Directory.Read.All` be dropped?

The first run showed the full set is sufficient, not that it is minimal. To test
the smaller set, as yourself:

```powershell
Add-Content lab	erraform.tfvars "scout_directory_read_all = false"
uv run poe lab-up                       # plan: 1 to destroy (the scout's Directory.Read.All grant)
```

Wait about 10 minutes, then repeat steps 5 to 8 (without `--record`). Report the
digest and the Collectors table. If the digest equals the full-set digest from
the same lab state and every collector is `complete`, `Directory.Read.All` can be
removed from the default. Any `http-403`, `partial`, or a different owner or
member count means it stays. Remove the line from `terraform.tfvars` (or set it
to `true`) and apply again to restore the grant.

## 10. Tear down (you approve the destroy)

Only when you are done with the lab. M2 uses it, so keep it running until then.
The rendered scope expires 7 days after creation; renew it with the command in
step 4 instead of rebuilding the lab.

```powershell
uv run poe lab-down                     # terraform destroy; review, then type yes
```

Removes: everything from step 4. The Key Vault is purged on destroy, so the name
can be reused. `scope.lab.yaml`, `.fns/` and `fixtures/lab-run-1/` stay on disk;
delete them if you do not want to keep the run. Deleting the free Azure account
or tenant itself is done in the portal.
