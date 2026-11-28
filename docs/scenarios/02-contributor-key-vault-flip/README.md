# 2. Contributor flips the vault to access policies (FIXTURE)

**Story.** `sp-batch-agent` writes batch output to `stbatch`. To "make it
work", it was given **Contributor** on the whole resource group, which also
holds `kv-crown`. Contributor has no data actions on the vault, so it looks
safe. But Contributor includes `Microsoft.KeyVault/vaults/write`, which can
switch the vault to the access-policy model or add an access policy for itself.

**Contract** (`tenant/contract.fns.yaml`):

```yaml
assume_compromised: sp:sp-batch-agent
must_not_reach:
  - resource: kv-crown
    operations: [secrets/get, secrets/list]
must_still_do:
  - resource: stbatch
    operations: [blob/write]
```

**Run:** `uv run fns demo contain --fixture docs/scenarios/02-contributor-key-vault-flip/tenant`

**Expected** ([full output](expected-tenant.txt)): `FAIL resource:kv-crown
secrets/get` and `secrets/list` through `kv-control-to-data` (Contributor allows
vaults/write), exit 1. `stbatch blob/write` is `inconclusive`: it is reachable in
the model, and a must-still-do needs an observed success to pass.

**Fix:** replace Contributor on the resource group with **Storage Blob Data
Contributor on `stbatch`** only. After the fix ([output](expected-fixed.txt))
both vault findings are `inconclusive` (not reached), the write is still
reachable, within budget, exit 0.

**Why the rule holds.** "With the Access Policy permission model, users with
the `Contributor`, `Key Vault Contributor`, or any role that includes
`Microsoft.KeyVault/vaults/write` permissions can grant themselves data plane
access by configuring a Key Vault access policy"
([Azure RBAC vs. access policies](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-access-policy)).
Whether switching a vault that is in RBAC mode also needs
`roleAssignments/write` on newer API versions is an open probe (M3); the path
states that assumption.
