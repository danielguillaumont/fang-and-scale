# 3. listKeys is data access (FIXTURE)

**Story.** `sp-rotation-agent` rotates storage keys, so it was given **Storage
Account Key Operator Service Role** on `stpayroll`. The role has no data
actions, so it looks like a control-plane role. But the account keys it can
list give full access to every blob.

**Contract** (`tenant/contract.fns.yaml`):

```yaml
assume_compromised: sp:sp-rotation-agent
must_not_reach:
  - resource: stpayroll
    operations: [blob/read, blob/write]
```

**Run:** `uv run fns demo contain --fixture docs/scenarios/03-listkeys-is-data-access/tenant`

**Expected** ([full output](expected-tenant.txt)): `FAIL resource:stpayroll
blob/read` and `blob/write` through `listkeys-data`, exit 1. The path assumes
Shared Key is allowed (Azure's default), because the storage account's
settings read is not in this scenario's scope.

**Fix:** if the agent only needs to read account metadata, give it **Reader**;
if it must rotate keys, disallow Shared Key authorization on the account so
the keys no longer open the data. After the Reader fix
([output](expected-fixed.txt)) both findings are `inconclusive` (not
reached), within budget, exit 0.

**Why the rule holds.** "Storage account access keys provide full access to
the storage account data and the ability to generate SAS tokens", and the
built-in roles with `listkeys/action` include "Owner, Contributor, Storage
Account Key Operator Service Role"
([Manage storage account access keys](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage)).
