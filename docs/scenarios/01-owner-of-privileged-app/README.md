# 1. The agent owns a privileged application (FIXTURE)

**Story.** `sp-report-agent` builds reports. Someone registered `app-deployer`
from the agent's pipeline, so the agent became its **owner**, and the agent
holds Microsoft Graph `Application.ReadWrite.OwnedBy` to manage its own app
registrations. `app-deployer` can read secrets in `kv-crown`. If the agent is
compromised, the attacker adds a client secret to `app-deployer` and signs in
as it.

The tenant also shows the new credential metadata collector: `app-deployer`
has one client secret, collected as metadata only (key ID, name, start, end),
never its value.

**Contract** (`tenant/contract.fns.yaml`):

```yaml
assume_compromised: sp:sp-report-agent
must_not_reach:
  - resource: kv-crown
    operations: [secrets/get]
```

**Run:** `uv run fns demo contain --fixture docs/scenarios/01-owner-of-privileged-app/tenant`

**Expected** ([full output](expected-tenant.txt)): `FAIL resource:kv-crown
secrets/get`, exit 1. The path:

1. `assume-compromised` sp-report-agent
2. `snapshot` it holds Application.ReadWrite.OwnedBy
3. `owner-adds-credential` it owns app-deployer, adds a credential, signs in as it
4. `snapshot` app-deployer has Key Vault Secrets User at kv-crown
5. `rbac-data-action` getSecret on kv-crown

**Fix:** remove the agent as owner of `app-deployer` (or drop
`Application.ReadWrite.OwnedBy` if the agent does not manage apps). After the
fix ([output](expected-fixed.txt)) the target is not reached: `inconclusive`
(nothing passes on modeled evidence), within budget, exit 0.

**Why the rule holds.** Microsoft Graph's permissions reference describes
Application.ReadWrite.OwnedBy as managing, including the secrets of, the
applications the caller owns, and nothing else
([permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference#applicationreadwriteownedby));
adding a password is
[`addPassword`](https://learn.microsoft.com/graph/api/application-addpassword).
