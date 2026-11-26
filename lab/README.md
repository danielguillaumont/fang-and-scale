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

Not in the lab (yet): Log Analytics and diagnostic settings (M4), and a deny
assignment. Deny assignments cannot be created directly; the bundled demo fixture
covers them.

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
