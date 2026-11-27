# M4 strikes plan (K5): `fns strike`

**Status: approved 2026-11-26, with SD1 to SD5 (end of this file). Build step 1,
the write gate, is done (see "Build status"). There is still no strike code.** It covers
the four lab strikes from `docs/milestones/M4.md` K5, and their re-runs after
harden (D6). The live order and the log path check are in
`docs/milestones/M4-plan.md`.

## The rules this plan keeps

These are your D4 conditions. Each one maps to a section below and to tests that
exist before any live run.

1. **Stop at the last reversible step.** A strike shows what the agent *can* do
   and stops there. It never assigns a directory role to anything. It proves
   the agent can write role assignments without making one that grants power
   (section "The stop line").
2. **Every write has an undo**, tested offline against a fake tenant:
   - credentials live 1 day at most;
   - every write and undo goes in the journal before it is sent and again
     after;
   - a read-only check after cleanup proves the state is back where it started;
   - an emergency cleanup section in the runbook covers a dead session.
3. **Only lab-created objects.** The scope gate allows a write only to an object
   Terraform created in `rg-fns-lab` or in Entra for the lab. Fuzz tests cover
   this.
4. **Every Graph write is listed below, in order, with its undo.** Nothing else
   is sent.

Rule 1 of `CLAUDE.md` still holds: only `strike` (and later `harden --apply`)
may write. It writes only to the lab, and only after `--approve <plan-hash>`.

## The strikes

All strikes run as `sp-billing-agent`, the assumed-compromised identity, with
the 1-day certificate from the M3 runbook. S4 is the one exception, and it says
so. `<run>` is the strike run ID, and every object a strike creates carries it
in its name.

### Before harden (session C)

**S1. listKeys on the payroll account** (ARM, Contributor)

| # | Request | Why | Undo |
| --- | --- | --- | --- |
| 1 | `GET .../storageAccounts/stpayroll<suffix>` | pre-state: `keyCreationTime.key1` and `.key2` | none (read) |
| 2 | `POST .../storageAccounts/stpayroll<suffix>/listKeys` | **the strike** | see 3 and 4 |
| 3 | `POST .../regenerateKey` `{"keyName":"key1"}` | the keys from step 2 become worthless | not undone: the account ends up safer |
| 4 | `POST .../regenerateKey` `{"keyName":"key2"}` | the same | as 3 |
| 5 | `GET .../storageAccounts/stpayroll<suffix>` (as the scout) | verify: both `keyCreationTime` values are later than step 2 | |

Step 2's response holds both account keys. The transport drops the `keys` field
before the response reaches the journal, the console or a fixture (section
"Secrets in responses"). Steps 3 and 4 are SD1.

**S2. A tag on the vault** (ARM `vaults/write`, Contributor)

| # | Request | Why | Undo |
| --- | --- | --- | --- |
| 1 | `GET .../vaults/kv-crown-<suffix>` | pre-state: `tags`, journaled exactly | none |
| 2 | `PATCH .../vaults/kv-crown-<suffix>` with body `{"tags": <pre-state tags> + {"fns-strike": "<run>"}}` | **the strike**: a control-plane write | step 3 |
| 3 | `PATCH .../vaults/kv-crown-<suffix>` with body `{"tags": <pre-state tags>}` | undo | |
| 4 | `GET .../vaults/kv-crown-<suffix>` (as the scout) | verify: `tags` equals the pre-state, and `properties` is unchanged | |

The body only ever contains `tags`. The gate refuses a `vaults/write` body with
any other key: never `properties`, so never `enableRbacAuthorization`, which is
the real escalation.

**S3. The owner adds a credential** (Graph, `Application.ReadWrite.OwnedBy`,
owner of `app-escalation-target`)

| # | Request | Why | Undo |
| --- | --- | --- | --- |
| 1 | `GET /v1.0/applications/{target-app}?$select=id,appId,displayName,tags,passwordCredentials` | pre-state, and the live lab check (section "Lab objects only") | none |
| 2 | `POST /v1.0/applications/{target-app}/addPassword` `{"passwordCredential":{"displayName":"fns-strike-<run>","endDateTime":"<now + 1 h>"}}` | **the strike** | step 3 (or S4's last step) |
| 3 | `POST /v1.0/applications/{target-app}/removePassword` `{"keyId":"<keyId from 2>"}` | undo | |
| 4 | `GET /v1.0/applications/{target-app}?$select=passwordCredentials` (as the scout) | verify: no `keyId` from step 2, and the same credential count as step 1 | |

Step 2's response includes `secretText`. Without SD2 the transport drops it, and
the strike ends at step 3. With SD2 it is kept in memory only, for S4.

**S4. Role assignment capability, then a self-granted app role** (SD2)

You asked for proof that the agent can write role assignments, with no
directory role assigned to anything. In the lab, the agent's route to role
assignments runs through S3. It adds a credential to `app-escalation-target`,
which holds Graph `AppRoleAssignment.ReadWrite.All`. That permission can grant
any Graph permission, including `RoleManagement.ReadWrite.Directory`, and so
any directory role. S4 shows that route works, and stops before anything that
grants power.

| # | Request | As | Why | Undo |
| --- | --- | --- | --- | --- |
| 1 | `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` (client credentials, `https://graph.microsoft.com/.default`), with S3's credential | `app-escalation-target` | sign in with the credential the agent added | nothing to undo; the token is held in memory only |
| 2 | (no request) decode the token's `roles` claim | | **capability proof:** `AppRoleAssignment.ReadWrite.All` is present. The agent can now write app role assignments, and through them directory roles | |
| 3 | `PATCH /v1.0/applications/{target-app}` `{"appRoles":[<pre-state roles>, {"id":"<new guid>","value":"fns.strike.marker","allowedMemberTypes":["Application"],"isEnabled":true,"displayName":"Fang & Scale strike marker <run>","description":"Grants nothing"}]}` | agent | a role that grants nothing, on a lab app | steps 6 and 7 |
| 4 | `POST /v1.0/servicePrincipals/{target-sp}/appRoleAssignedTo` `{"principalId":"{agent-sp}","resourceId":"{target-sp}","appRoleId":"<new guid>"}` | `app-escalation-target` (token from 1) | **the self-grant:** the agent receives an app role, through the escalated identity. The resource is a lab app, never Microsoft Graph | step 5 |
| 5 | `DELETE /v1.0/servicePrincipals/{target-sp}/appRoleAssignedTo/{assignment id}` | `app-escalation-target` | undo 4 | |
| 6 | `PATCH /v1.0/applications/{target-app}` (the marker role with `"isEnabled": false`) | agent | Graph refuses to remove an enabled role | |
| 7 | `PATCH /v1.0/applications/{target-app}` `{"appRoles": <pre-state roles>}` | agent | undo 3 | |
| 8 | S3 step 3, `removePassword` | agent | undo S3 | |
| 9 | as the scout: `GET .../appRoleAssignedTo`, `GET /applications/{target-app}?$select=appRoles,passwordCredentials` | scout | verify: no assignment, the same roles as before, no strike credential | |

What S4 does **not** do:

- assign any directory role;
- call `/roleManagement/*` or `/directoryRoles/*` at all;
- create an `appRoleAssignment` whose resource is Microsoft Graph, or any SP
  outside the lab;
- use the token from step 1 for anything except step 4 and its undo in step 5.

Steps 1 and 2 alone already prove the capability. Steps 3 to 7 exist so that the
`app-role-assignment-by-workload` rule has a real event to fire on, which is SD2.

Graph has no way to revoke an app-only token. After step 8 the token from step 1
stays valid until it expires (typically 60 to 90 minutes). It exists only in the
strike process's memory, and the process exits after the run.

### After harden (session D, D6): required denials

After harden, the agent has neither Contributor nor `OwnedBy`. It still owns
`app-escalation-target`, which is the accepted survivor from M2. These attempts
must all be **denied**. Each denial is an observed result for the contract item
in the right-hand column. If one succeeds, its undo runs immediately and the
contract fails (exit 1).

| # | Request (as the agent) | Expected | Undo if it succeeds | Contract item it observes |
| --- | --- | --- | --- | --- |
| D-1 | `POST /applications/{target-app}/addPassword` (1 h) | 403 | `removePassword` | the first hop of every escalation path ("ownership without `OwnedBy`", FINDINGS) |
| D-2 | `POST /applications/{id-verifier-app}/addPassword` (1 h) | 403 | `removePassword` | `application:id-verifier credentials/update`, and `directory:tenant applications/credentials/update` |
| D-3 | `POST /applications/{scout-app}/addPassword` (1 h) | 403 | `removePassword` | `application:sp-fns-scout credentials/update` |
| D-4 | `POST /applications/{id-verifier-app}/owners/$ref` `{"@odata.id":".../directoryObjects/{agent-sp}"}` | 403 | `DELETE /applications/{id-verifier-app}/owners/{agent-sp}/$ref` | `application:id-verifier owners/update` |
| D-5 | `POST /applications/{scout-app}/owners/$ref` (the same) | 403 | the same, on the scout app | `application:sp-fns-scout owners/update` |

`directory:tenant roleAssignments/write` gets **no direct attempt**. The only
direct attempt is a directory role assignment, and if it succeeded it would
break your rule. Its escalation path is refuted by D-1, an observed denial of
the path's first hop. Its direct operation stays unobserved, so under the
current verdict rules the item stays `inconclusive`. SD3 is the decision.

S1 and S2 after harden (`listKeys` and the vault tag, both 403 without
Contributor) are optional (SD4). The M3 read probes already observe those items.

## The stop line

| Strike | Last step taken | First step never taken |
| --- | --- | --- |
| S1 | read the keys (then make them worthless) | use a key |
| S2 | add a tag | touch `properties` (switching the vault out of RBAC mode) |
| S3 | add a 1-hour credential | sign in with it (that is S4) |
| S4 | the target's token shows it can write role assignments; a self-grant of a role that grants nothing, on a lab app | grant any Graph permission; assign any directory role |

## Lab objects only: the scope gate's write forms

The gate has no write forms today. This plan adds one block to the scope,
rendered by Terraform from the lab's own resources, so it can only name objects
Terraform created:

```yaml
strike:
  expires_at: <1 hour after the plan was made>
  targets:                         # rendered by lab/scope.tf, never hand-written
    - kind: arm
      id: /subscriptions/<sub>/resourceGroups/rg-fns-lab/providers/Microsoft.Storage/storageAccounts/stpayroll<suffix>
    - kind: arm
      id: /subscriptions/<sub>/resourceGroups/rg-fns-lab/providers/Microsoft.KeyVault/vaults/kv-crown-<suffix>
    - kind: graph-application      # app-escalation-target, id-verifier, sp-fns-scout
      id: <object id>
    - kind: graph-service-principal  # app-escalation-target, sp-billing-agent
      id: <object id>
    - kind: graph-group            # grp-fns-billing (D3): listed, but no write form names it
      id: <object id>
  operations:                      # exactly these; anything else is denied
    - arm:POST Microsoft.Storage/storageAccounts/listKeys
    - arm:POST Microsoft.Storage/storageAccounts/regenerateKey
    - arm:PATCH Microsoft.KeyVault/vaults (tags only)
    - graph:POST /applications/{id}/addPassword
    - graph:POST /applications/{id}/removePassword
    - graph:PATCH /applications/{id} (appRoles only)
    - graph:POST /servicePrincipals/{id}/appRoleAssignedTo
    - graph:DELETE /servicePrincipals/{id}/appRoleAssignedTo/{id}
    - graph:POST /applications/{id}/owners/$ref      # D-4 and D-5 only
    - graph:DELETE /applications/{id}/owners/{id}/$ref
    - token:client_credentials app-escalation-target  # S4 step 1 only
```

**What the gate checks on every write**, on top of its read rules (tenant
pinning, expiry, budget):

1. The operation is one of the listed forms, matched on method plus path
   template after canonicalization. A path with `..`, `//`, percent-encoded
   `/` or `.`, or a trailing slash is refused, never normalized into a match.
   So is a query string on a write. Case is compared as each API defines it:
   ARM provider and type names case-insensitively, Graph segments exactly.
2. **Every object ID in the path and in the body** is in `targets` with the
   right kind. The body IDs are `principalId`, `resourceId`, `@odata.id` and
   `keyId`'s application. `appRoleAssignedTo` needs `resourceId` and the path SP
   to be the same lab SP, and `principalId` to be `sp-billing-agent`.
3. **Body allowlists:**
   - a vault `PATCH` contains only `tags`;
   - an application `PATCH` contains only `appRoles`, and every role in it is
     either one from the pre-state or the strike's marker;
   - `addPassword`'s `endDateTime` is at most 1 hour from now.
4. **A hard denylist that no scope can lift:**
   - `/roleManagement/`, `/directoryRoles/`, `/directory/`, `oauth2PermissionGrants`;
   - any `appRoleAssignedTo` or `appRoleAssignments` whose resource is the
     Microsoft Graph service principal (`00000003-0000-0000-c000-000000000000`)
     or anything outside `targets`;
   - `Microsoft.Authorization/*` writes;
   - `vaults/accessPolicies`.
5. **A live check before the first write to each Graph object:** a `GET` that
   must show the lab tags (`project=fang-and-scale`, `purpose=lab`) and the
   display name Terraform gave it. The gate requires both the rendered target
   and the live tag check, so a stale scope file can't point at a recreated
   object.
6. The request belongs to the approved plan: its position, method, path and body
   digest match the plan entry the hash covers (next section).

**Tests (offline, before any live run):**

- A negative test for each rule above.
- **Hypothesis fuzz tests** of the write gate:
  - random methods, hosts, ARM and Graph paths, object IDs (in `targets`, near
    misses, other kinds), path tricks (case, encoding, `..`, `//`, trailing
    slashes, `;`, unicode look-alikes), bodies with extra keys, and expiries;
  - the property: a write is allowed **only if** it is exactly a planned step,
    its form is listed, every ID in it is a target of the right kind, and the
    scope and plan are both unexpired;
  - a second property: nothing on the hard denylist is ever allowed, whatever
    the scope says.
- A test that `lab/scope.tf` renders `targets` only from Terraform resource
  references, never from literals or `data.*` lookups.

## Plan, approval, journal and cleanup

1. **`fns strike plan --strikes S1,S2,S3,S4 --scope scope.lab.yaml`.** It
   resolves every target (reads only) and prints the full ordered request list
   from the tables above, with every body. It writes `strike-plan.json` and
   prints `plan sha256:<hash>`.
   - The hash covers the canonical JSON of the list, the scope digest, the run
     ID, the agent's object ID and the expiry (1 hour).
2. **`fns strike run --plan strike-plan.json --approve <hash>`.** It recomputes
   the hash and refuses on any difference: a changed file, a changed scope, an
   expired plan, or another signed-in identity (the M3 identity check).
3. **Journal.** Before each request it writes an `intent` row: step, method,
   path, body digest and undo. After the request it writes a `result` row:
   status, the response with secrets removed, and the IDs it learned, such as
   `keyId` and the assignment ID. These rows are in the same SQLite journal as
   M3, so `fns report` and the verifier can read them.
4. **Undo always runs.** The undo for every step that wrote is in a `finally`,
   in reverse order. That covers a failed step, Ctrl-C and an exception. Each
   undo is journaled the same way.
5. **Verification** reads every strike object back as `sp-fns-scout`, a
   different, read-only identity, and compares it with the journaled pre-state.
   Any difference exits 5 and prints the emergency cleanup section.
6. **`fns strike cleanup --journal <path> --approve <hash>`.** It finds every
   write without a successful undo and runs those undos, using the same plan
   and hash. This is the resume path after a crash, and the first command in
   the emergency runbook.

**Tests (offline):** a fake ARM and Graph tenant (as in
`tests/prove/test_live_probes.py`) runs each strike. The tests then check:

- the end state equals the start state;
- the journal shows intent, then result, then undo;
- a failure injected at every step still ends clean;
- `cleanup` after a simulated crash at every step ends clean;
- the verification catches an undo that the fake silently drops.

## Credentials

| Credential | Lifetime | Created by | Removed by |
| --- | --- | --- | --- |
| `sp-billing-agent` certificate | at most 23 hours (M3 runbook, step 5) | you | you, right after the run, with the empty-list check |
| `sp-fns-scout` certificate (verification) | at most 23 hours | you | you |
| S3's password on `app-escalation-target` | `endDateTime` 1 hour | the strike | S3 step 3 or S4 step 8, verified by the scout |
| The `app-escalation-target` token (S4) | until it expires, typically 60 to 90 minutes; it can't be revoked | the strike | it is never written down, and the process exits after the run |

## Secrets in responses

Three responses contain secrets:

- `listKeys` returns `keys`;
- `addPassword` returns `secretText`;
- the token endpoint returns `access_token`.

The transport removes those fields **before** the response object exists for
any other code. They go into a short-lived in-memory holder: S4 alone reads the
password and the token, and nothing reads the keys. Tests run each strike
against the fake tenant and assert:

- no journal row, log line, console output, report or fixture contains a
  planted secret value;
- the `fns.fixtures` sanitizer would reject one if it did.

## Detection mapping (session C)

The monitored identities are `sp-billing-agent` and `app-escalation-target`.

| Strike | Event | Rule | Table |
| --- | --- | --- | --- |
| S1 | `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` | `storage-listkeys-by-workload` | `AzureActivity` |
| S2 | `MICROSOFT.KEYVAULT/VAULTS/WRITE` | `keyvault-control-plane-write-by-workload` | `AzureActivity` |
| S3 | "Update application – Certificates and secrets management" | `app-credential-added-by-workload` | `AuditLogs` |
| S4 | the target's sign-in | none yet: a rule over `AADServicePrincipalSignInLogs`. The log path check (M4-plan step 1) showed the table fills on Entra ID Free (2026-11-27); a certificate sign-in logs `ClientCredentialType` = `clientAssertion` | `AADServicePrincipalSignInLogs` |
| S4 | "Add app role assignment to service principal" | `app-role-assignment-by-workload` | `AuditLogs` |

You run one KQL query per strike and paste the result (D5). The runbook gives the
query for each.

## Emergency cleanup (outline of the runbook section)

For when the session dies, `fns strike cleanup` fails, or you are unsure. The
steps, all as **yourself** (not the agent):

1. `fns strike cleanup --journal <path> --approve <hash>`. If it succeeds, go
   to step 4.
2. If it fails, undo by hand, in this order. Each step is safe to repeat:
   - **S4:**
     - list `appRoleAssignedTo` on the target SP and delete any assignment
       whose `principalId` is the agent;
     - set the marker role to `isEnabled: false`, then remove it with
       `az rest --method patch` on the application.
   - **S3:**
     - `az ad app credential list --id <target appId>`;
     - delete every credential named `fns-strike-*`
       (`az ad app credential delete --id <appId> --key-id <keyId>`).
   - **S2:** `az keyvault update` cannot remove only one tag. Use
     `az resource tag --ids <vault id> --tags <the pre-state tags from the
     journal or the plan>`.
   - **S1:** `az storage account keys renew --key key1` and `--key key2`.
   - **D-1 to D-5:** if any of them succeeded, delete the credential or the
     owner reference it created (the same commands as S3, plus
     `az ad app owner remove`).
3. If the journal is lost, look for objects by name instead: any credential
   named `fns-strike-*`, any app role whose `value` is `fns.strike.marker`, any
   assignment to the agent on a lab SP, and any vault tag `fns-strike`.
4. Delete the agent's and the scout's certificates, with the empty-list checks
   (M3 runbook, step 7).
5. If none of this works, `uv run poe lab-down` destroys every object a strike
   can touch. The strikes write only to lab objects, so nothing outside the lab
   needs cleaning.

The runbook section gets the exact commands, written against the journal's
field names.

## What gets built, in order (after you approve)

1. **The write gate:** forms, targets, the denylist, body allowlists, and the
   negative and fuzz tests. Then `lab/scope.tf` renders `strike.targets`, with
   its test.
2. **The secret-stripping transport**, and the planted-secret tests.
3. **`fns strike plan`, `run` and `cleanup`:** the plan hash, the journal, undo
   in `finally`, and the verification. They are tested against the fake tenant,
   including a failure at every step.
4. **The strikes S1 to S4 and the post-harden attempts D-1 to D-5**, each with
   its undo and verification tests.
5. **`docs/runbooks/m4-live-run.md`**, sessions C and D: the commands, the
   expected output, the KQL per strike, the stop rules and the emergency
   cleanup.

Each is its own PR with CI green. Nothing runs live until the runbook is merged
and you start the session.

## Build status

**Step 1, the write gate: built** (`src/fns/scope/writes.py`, `Gate.check_write`
and `Gate.call_write`). Nothing calls it except tests.

- **Tests:** a negative test per rule (`tests/scope/test_gate_writes.py`), and
  Hypothesis properties (`tests/scope/test_gate_writes_fuzz.py`):
  - a write is allowed exactly when every part of it is good, checked against an
    independent oracle;
  - a first-party object is always a hard deny;
  - no scope lifts the denylist: valid, forged past validation, or any committed
    scope file with a strike block added.
- **Mutation check:** switching off the denylist, the body check or the SD2
  marker rule each fails tests.

Where the build differs from the text above, and why:

| Plan said | Built | Why |
| --- | --- | --- |
| a `strike.operations` list | the write forms are listed under `allowed_operations.strike`, and validation refuses any write there that is not one of the ten forms | one place for operations, as for every other verb |
| no query string on a write | Graph writes: none. ARM writes: exactly `api-version=<pinned>` (Storage `2023-05-01`, Key Vault `2023-07-01`) | ARM requires `api-version`; pinning it is the Key Vault data-plane rule again |
| denylist: role, grant and authorization endpoints | also `$batch`, all of `appRoleAssignments`, `federatedIdentityCredentials`, and writes to `Microsoft.Insights`, `Microsoft.AadIam`, `Microsoft.OperationalInsights` and `Microsoft.SecurityInsights` | a batch can carry any request, and a strike must never switch off the logs it is measured by |
| `graph-group` target kind | left out | no write form names a group |
| a `token:` form for S4 step 1, acting as `app-escalation-target` | not yet: every write must be made signed in as a test identity | it lands with S4, under its own decision |
| `lab/scope.tf` renders `strike.targets` | not yet | the live scope gets write forms only when strike code exists to use them |
| `removePassword` and the assignment `DELETE` bound to IDs the run created | bound to lab objects only; the plan binding (step 3) will bind them to IDs from the journal | the gate cannot learn a `keyId` before the strike runner exists |

**SD2's condition** (the marker role is defined only on a lab-created app,
never on Microsoft Graph or a first-party app) is enforced in three places:

- a scope cannot name a first-party ID as a target;
- the live check refuses a service principal owned by another tenant, or with a
  first-party `appId`;
- an `appRoleAssignedTo` write is allowed only for a marker role that this run's
  gate let through, on the service principal's own lab application.

Each place has a negative test.

The denylist also reads text in request bodies. So an app role whose description
contained a denied word, such as "directory", could not be written back by the S4
undo. The gate refuses the write rather than allowing it, and the lab apps define
no app roles (`lab/identities.tf`), so this can't happen today.

## Decisions for you

Approved 2026-11-26:

- **SD1: a.** Regenerate both keys after `listKeys`, verified.
- **SD2: b**, with the condition above, enforced by the gate.
- **SD3: a.** `directory:tenant roleAssignments/write` stays `inconclusive` after
  harden. This is a deliberate limit, explained in the README's "Evidence
  ladder".
- **SD4: b.** No re-run of S1 and S2. D6 still applies to the Graph strikes.
- **SD5: yes.**

The options as they were offered:

- **SD1. S1's undo: regenerate both payroll keys.**
  - **a.** Yes. **(Recommended:** the keys were in the tool's memory, and
    regenerating makes any copy worthless. Nothing in the lab uses shared keys.)
  - **b.** No undo: S1 changes nothing, so leave the keys.
- **SD2. How far S4 goes.**
  - **a.** Steps 1 and 2 only: sign in as the target and show
    `AppRoleAssignment.ReadWrite.All` in its token. This makes no assignment, so
    `app-role-assignment-by-workload` can't be tested. Its result is recorded as
    "not exercised".
  - **b.** Steps 1 to 9: add the self-grant of the marker role (grants nothing,
    on a lab app), then undo it. **(Recommended:** the rule gets a real event,
    and the role and its resource are both lab objects that grant nothing.)
  - **c.** No S4: the strikes stop at S3's credential. The capability stays
    modeled.
- **SD3. `directory:tenant roleAssignments/write` after harden.**
  - **a.** Accept `inconclusive` for this one item, refuted at rung 3 through D-1,
    with the contract's `max_inconclusive` covering it and a reason.
    **(Recommended.)**
  - **b.** Change the verdict rules so that a path refuted at rung 3 with **no**
    remaining path counts as a pass for operations that have no safe direct
    attempt. This changes the evidence model, so it needs its own plan.
- **SD4. Re-run S1 and S2 after harden** (both should be 403 without
  Contributor).
  - **a.** Yes, as cheap extra observed denials, with the same undo if one
    succeeds.
  - **b.** No: the M3 read probes already cover those items. **(Recommended**,
    for fewer writes.)
- **SD5. The order of the first build PRs.** The write gate and its fuzz tests
  come first and are merged before any strike code exists, so you can review the
  boundary on its own. **(Recommended: yes.)**

## Sources

- Graph `application: addPassword` and `removePassword`:
  <https://learn.microsoft.com/graph/api/application-addpassword>,
  <https://learn.microsoft.com/graph/api/application-removepassword>
- Graph `servicePrincipal: appRoleAssignedTo` (create and delete):
  <https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignedto>
- Graph application `appRoles` (disable before removing):
  <https://learn.microsoft.com/entra/identity-platform/howto-add-app-roles-in-apps>
- Storage `listKeys` and `regenerateKey`:
  <https://learn.microsoft.com/rest/api/storagerp/storage-accounts/list-keys>,
  <https://learn.microsoft.com/rest/api/storagerp/storage-accounts/regenerate-key>

The permission each request needs is checked against these pages in the
write-gate PR, and the live run settles it. Any 403 where this plan expects
success, or the reverse, is a FINDINGS entry.
