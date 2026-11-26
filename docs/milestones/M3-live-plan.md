# M3 P5: live plan (probes, data-plane scope gate, Sigstore in CI)

**Status: approved and built, 2026-11-26.** V1 to V6 are approved:
- V3 is staging only until the repository is public;
- V6 has conditions.

Both are recorded in `docs/DECISIONS.md`. The offline PRs #29 to #34 are merged.
**The runbook is `docs/runbooks/m3-live-run.md`.** Section 10 below is the
original draft, kept for the record and superseded.

Corrections from the build, which the runbook already follows:

- **6 `prove` operations, not 5.** The V6 pre-flight adds
  `arm:Microsoft.KeyVault/vaults/secrets/read`, a metadata read that never
  returns the value.
- **Data-plane reads are bound to their resource** (`data_objects` in
  `scope.yaml`), so the payroll path cannot be requested from the invoices
  account. The test identity also carries `app_id`, for the V4 `appid` check.
- **14 requests, not "at most 13".** That is 13 distinct probes plus the
  pre-flight. The journal holds 17 `probe:` steps, one per frozen spec, and 14
  gate decisions, because a question asked for two findings is sent once.
- **The apply is not local-only.**
  - The secret gets the tag `fns-data = synthetic` (an in-place update).
  - The scope is renewed, because it expires on 2026-12-03.
  - Expected plan: 2 to add, 1 to change, 2 to destroy.
- **Both certificates last at most 1 day.** The agent and the scout each sign in
  under a temporary `AZURE_CONFIG_DIR`.

M3's gate (PLAN §8): live probes confirm or refute each path, `fns prove` runs
under `id-verifier`, and the bundle verifies with Sigstore.

## What I need from you

**Decisions** (section 9 has the options). Each one has a recommendation:

| # | Question | Recommendation |
| --- | --- | --- |
| V1 | What does "`fns prove` under `id-verifier`" mean, when the verifier makes no Azure call? | The verifier runs with **no Azure credential at all**, not a separate read-only one. `id-verifier` stays in the lab, unused in M3. Change the PLAN §8 wording |
| V2 | How does the probe check `blob/read`? | `HEAD` (Get Blob Properties). It needs the same data action as `GET`, and no blob content is transferred |
| V3 | What does Sigstore sign? | CI re-runs the verifier on the **sanitized recording** of the live run (`fixtures/lab-run-3`) and signs that. The live bundle stays local, signed with the offline test key |
| V4 | Whose identity counts as the prober? | **Principal pinning.** For every `prove` call, the gate compares the token's `oid` with `test_identities`, and does not trust a caller argument |
| V5 | Which errors count as a denial? | Only authorization errors (the codes listed in section 1). A firewall denial, a 401, a 404 or a 5xx is `unknown` |
| V6 | May the `secrets/get` probe send a real `GET` for the synthetic secret? | Yes. The secret is synthetic, the probe is expected to be denied, and an allowed response body is dropped unread |

**Reviews.** Four offline PRs come first (section 8). The scope-gate PR is a
rule-2 change, so it is plan-first and comes with negative tests.

**Actions in the tenant** (the draft runbook, section 10). You run all of them:

- One Terraform apply. It re-renders `scope.lab.yaml` with a `prove` block,
  renews its expiry, and tags the synthetic secret `fns-data = synthetic`. That
  last change is in place, and the value is unchanged.
- A short-lived certificate on `sp-fns-scout` for a fresh scout, removed at the
  end. This is the same as in M1 and M2.
- A short-lived certificate on **`sp-billing-agent`**, so the probes run as the
  test identity. It is removed straight after the probes.
- Nothing in Azure for Sigstore. CI needs `id-token: write` on one job, on
  `main` only.

## 1. What each probe does in the tenant

The seeded lab contract freezes 17 probe specs. They are 13 distinct probes
(9 rung-2 and 4 rung-3). Each distinct probe is sent once, and the secret read
first sends a metadata pre-flight (V6). So a live `fns prove` sends **14
requests**, all of them `GET` or `HEAD`, all as `sp-billing-agent`. Contract items on `directory:tenant` and on the two
applications have no probe. Their paths start with an escalation write (E2), so
they stay `fail` at rung 1.

### Rung 2: `arm-permissions` (9 probes, already built)

The probe sends `GET https://management.azure.com{scope}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01`.
Each probe asks whether its action is listed at that scope:

| Scope (resource) | Action asked about | For item |
| --- | --- | --- |
| `kv-crown-<suffix>` | `Microsoft.KeyVault/vaults/secrets/getSecret/action` (data) | `secrets/get` |
| `kv-crown-<suffix>` | `Microsoft.KeyVault/vaults/secrets/readMetadata/action` (data) | `secrets/list` |
| `kv-crown-<suffix>` | `Microsoft.KeyVault/vaults/write` | both, the `kv-control-to-data` path |
| `stpayroll<suffix>` | `.../blobServices/containers/blobs/read` (data) | `blob/read` |
| `stpayroll<suffix>` | `Microsoft.Storage/storageAccounts/listKeys/action` | `listKeys`, and the `listkeys-data` path |
| `stinvoices<suffix>` | `.../blobs/read`, `.../blobs/write`, `.../blobs/add/action` (data) | `must_still_do` |
| `stinvoices<suffix>` | `Microsoft.Storage/storageAccounts/listKeys/action` | `listKeys` |

**Why it is non-destructive.**

- It is a read of the caller's own effective permissions, and it changes nothing.
- ARM writes no Activity Log event for a `GET`.
- The gate classifies the operation as a read (`arm:Microsoft.Authorization/permissions/read`).

**What it records.** The HTTP status, the request id, and "listed" or "not listed".
It does not record the response body.

**Its limit.** The API ignores deny assignments and conditions, which is why it is
rung 2 and not rung 3.

### Rung 3: `data-read` (4 probes, to build)

| Probe | Request (as `sp-billing-agent`) | Expected | Why non-destructive |
| --- | --- | --- | --- |
| KV `secrets/get` | `GET https://kv-crown-<suffix>.vault.azure.net/secrets/payroll-db-password?api-version=7.4` | `403`, `innerError.code` `ForbiddenByRbac`. The vault uses RBAC, and Contributor has no data actions | A read. If it were allowed, the body (the synthetic `random_password`, which is already in the Terraform state) is dropped unread and never stored, logged or hashed (V6) |
| KV `secrets/list` | `GET https://kv-crown-<suffix>.vault.azure.net/secrets?api-version=7.4` | `403` `ForbiddenByRbac` | A read. If allowed, it returns secret names and metadata, never values. The body is dropped |
| Payroll `blob/read` | `HEAD https://stpayroll<suffix>.blob.core.windows.net/payroll/employees-SYNTHETIC.csv` (bearer token, `x-ms-version: 2023-11-03`) | `403`, `x-ms-error-code: AuthorizationPermissionMismatch`. The agent has no blob data role on payroll | `HEAD` returns properties only, no content (V2). The probe never uses a shared key and never calls `listKeys` |
| Invoices `blob/read` | `HEAD https://stinvoices<suffix>.blob.core.windows.net/invoices/invoice-0001-SYNTHETIC.json` | `200`. The agent has Storage Blob Data Contributor there (legitimate use) | As above. This is the probe that should produce M3's one real `pass` |

**Outcome rule (V5).** It is conservative (rule 4):

- `allowed` only on `200`.
- `denied` only on `403` with an authorization code:
  - Key Vault: `Forbidden`, with inner code `ForbiddenByRbac` or `AccessDenied`;
  - Storage: `AuthorizationPermissionMismatch`.
- `unknown` for everything else, including:
  - `401` and `404`;
  - throttling and `5xx`;
  - a firewall denial (`ForbiddenByFirewall`, or `AuthorizationFailure` from a
    network rule). A network denial says nothing about an attacker on another
    network.

**What it records.** The status, the error code (header or body), the request id
and the duration. It never records a body. The documented codes above are
expectations. The run records the actual codes, and every difference becomes a
FINDINGS entry.

### What is never sent

- No `listKeys`. It is an `action` that returns keys, and the gate classifies it
  as a write.
- No `PUT`, `PATCH`, `POST` or `DELETE` to any data plane. The new grammar cannot
  even express them.
- No `vaults/write` or role assignment, and no Graph call as the agent.
- No shared key, SAS or connection string.
- No request to a host that is not the target's own data-plane host.
- R1 (does ARM authorize before it validates) is **not** part of P5. It sends
  writes and needs its own approval under `--approve <plan-hash>`.

### Side effects worth knowing

- **Certificate audit event.** Creating and deleting the certificate on
  `sp-billing-agent` writes Entra audit events ("Update application –
  Certificates and secrets management"). That is useful later: it is exactly
  what the M4 credential detection rule should see. No diagnostic settings exist
  before M4, so nothing is exported.
- **No data-plane logs.** Key Vault and storage diagnostic logs are not enabled
  in the lab, so the probes leave no data-plane log entries. Storage
  last-access-time tracking is off by default, and the lab does not turn it on.
- **Contract budget.** The scope budget is 500 calls and 15 minutes. Scout uses
  34 calls, and prove uses 14.

### Expected verdicts (unhardened lab)

These come from the hand-written `probes.json`, which is the hypothesis this run
tests. Any difference is a `model-gap` or a `platform-gap`, and it goes in FINDINGS.

| Item | Probes say | Verdict | Coverage |
| --- | --- | --- | --- |
| KV `secrets/get`, `secrets/list` | data read denied, data action not listed, **`vaults/write` listed** | `fail` | evaluated-only: the `kv-control-to-data` path is not refuted |
| payroll `listKeys`, invoices `listKeys` | `listKeys/action` listed | `fail` | evaluated-only |
| payroll `blob/read` | data read denied, **`listKeys` listed** | `fail` | evaluated-only: the `listkeys-data` path is not refuted |
| `directory:tenant` (2), both applications (4) | no probe (E2) | `fail` | modeled-only |
| invoices `blob/read` (must still do) | `HEAD` `200` | **`pass`** | **verified (observed)** |
| invoices `blob/write` (must still do) | data action listed, with no write probe (E4) | `inconclusive` | evaluated-only |

The expected summary is: passed 1, critical reachable 11, inconclusive 1, exit 1.
No `must_not_reach` can pass on the unhardened lab, because Contributor still
lists `vaults/write` and `listKeys`. Passes on forbidden items come after the M4
hardening apply.

## 2. The data-plane scope-gate change (P5.1)

This is a rule-2 change. It gets a plan-first PR, with negative tests written
before the code.

**Grammar** (`fns.models.operations`). Two new APIs, read-only by construction:

```
kv:GET /secrets
kv:GET /secrets/<name>            name: ^[0-9A-Za-z-]{1,127}$
blob:HEAD /<container>/<blob>     container: ^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){2,62}$
                                  blob: ^[A-Za-z0-9._-]{1,256}$  (flat names only)
```

- Any other method on `kv:` or `blob:` fails to parse, so the gate denies it as
  `MALFORMED_OPERATION`.
- Both forms are classified as reads.
- The scope lists **literal names**, not templates. So `scope.lab.yaml` names
  exactly the one secret and the two blobs that may be read.

**Gate checks** (`fns.scope.gate`, `fns.scope.targets`). The checks below are
added in order:

1. **Data-plane verbs.** `kv:` and `blob:` are allowed only under the verb
   `prove`. Every other verb is denied with a new reason,
   `DATA_PLANE_VERB_NOT_ALLOWED`, even if the scope file lists the operation.
   This is defence in depth, independent of what the scope says.
2. **Target.** The target must be the ARM ID of a resource of the matching type:
   `microsoft.keyvault/vaults` for `kv:`, `microsoft.storage/storageaccounts`
   for `blob:`. Anything else is `TARGET_KIND_MISMATCH`. The existing
   subscription and resource-group checks then apply unchanged.
3. **Host.** It must be exactly `<target name>.vault.azure.net` or
   `<target name>.blob.core.windows.net`, lower-cased, on port 443 and with no
   user info. Anything else is denied:
   - other vaults or accounts;
   - lookalike suffixes (`….vault.azure.net.example`);
   - sovereign-cloud hosts, `dfs.`, `queue.` and `file.`.
4. **Path.** It must be exactly the operation's path. Version segments are
   denied (`/secrets/<name>/<version>`).
5. **Query.**
   - Key Vault: only the pinned `api-version`.
   - Blob: no query string at all, which denies `comp=`, `restype=` and SAS
     parameters.
   - Key Vault list paging goes through the existing `check_next_link`, which
     allows only the query to change.
6. **Principal (V4).** For every `prove` call, `arm-permissions` included, the
   principal must be in `test_identities`. The principal is the `oid` of the
   pinned token (`PinnedTokens.signed_in_principal()`), and it is handed to the
   gate at construction. A caller-supplied `principal_id` that differs is
   denied. Check 10 already does this for `strike`, and P5 extends it to
   `prove`.

**Tokens** (`fns.scope.credentials`):

- `Api` gains `kv` (`https://vault.azure.net/.default`) and `blob`
  (`https://storage.azure.com/.default`).
- Every token's `tid` is checked as today.
- `oid` is read the same way as `tid`, without signature verification, for the
  same reason.

**Transport** (`fns.adapters.azure.http`):

- A data-plane transport that can send only `GET` or `HEAD`.
- It asserts that the method matches the operation's method.
- It never sends `x-ms-blob-*` or write headers.
- It reads at most 8 KiB of an error body (`status >= 400`) to find the error
  code, and drops every success body without reading it.

**Negative tests** (written first). Each one asserts a denial and that `fn` was
never invoked:

- `kv:` or `blob:` under `scout`, `contain`, `harden`, `molt` and `strike`;
- `kv:PUT`, `kv:DELETE`, `blob:PUT`, `blob:GET` and `kv:POST` (parse errors);
- a host for another vault, a lookalike suffix, an uppercase or IDN host, a
  port, user info, `http:`, and `vault.azure.cn`;
- the vault ARM ID used with a `blob:` operation, and a storage account in a
  resource group that is not allowed;
- a secret with a version segment, `..`, `%2F`, a trailing slash, and a blob
  name containing `/`;
- `?comp=list`, `?restype=container`, `?sv=…&sig=…`, and a Key Vault query
  other than `api-version`;
- a `nextLink` to another host or path;
- a principal not in `test_identities`, a token whose `oid` differs from the
  argument, and a token without an `oid`;
- an expired scope, a tenant mismatch, and an exhausted budget, on the new APIs;
- a Hypothesis fuzz that extends the existing gate fuzz to the new APIs: no
  generated out-of-scope call is allowed.

**Scope file.** `lab/scope.lab.yaml.tftpl` gains a `prove:` block:

- `arm:Microsoft.Authorization/permissions/read`;
- `kv:GET /secrets` and `kv:GET /secrets/payroll-db-password`;
- `blob:HEAD /payroll/employees-SYNTHETIC.csv` and
  `blob:HEAD /invoices/invoice-0001-SYNTHETIC.json`.

The names come from the Terraform resources, not typed by hand. `uv run poe schema`
regenerates the scope schema if the operation pattern changes.

## 3. The probe credential flow (P5.2)

- **CLI.** A new `fns prove --live` option, mutually exclusive with `--probes`. It
  builds `PinnedTokens` for the scope tenant, reads the signed-in principal, and
  refuses (exit 4) unless that principal is in `test_identities`. It then routes
  `arm-permissions` to `ArmPermissionsProbe` and `data-read` to `DataReadProbe`,
  both through one gate under `prove`.
- **Signing in.** You sign in as `sp-billing-agent` with a certificate that lasts
  one day, using `az ad app credential reset --create-cert --append`, as for the
  scout. The tool never sees the private key: tokens come from the Azure CLI
  session (README, "No secrets").
- **That session can write.** The agent has Contributor on the resource group and
  `Application.ReadWrite.OwnedBy`, and it owns `app-escalation-target`, so this
  is a real attacker foothold. The tool's gate refuses every write. The runbook
  keeps the session to the single `fns prove` command, then deletes the
  certificate and signs out.

## 4. The verifier and `id-verifier` (P5.3, decision V1)

As built (E6, E7), the verifier reads only `assertions.json`, the journal (read
only) and the artifacts, and it makes no network call. `fns.verify` may not
import `fns.scope`, so it could not make a gated Azure call even if it wanted
to. `id-verifier` already exists in the lab, with Reader on the resource group.

- **(A) Recommended.** The verifier holds no Azure credential at all, which is a
  stronger separation than holding a separate read-only one.
  - The bundle's verifier identity is the label passed with `--identity`, and, in
    CI, the Sigstore certificate identity.
  - `id-verifier` stays in the lab, unused in M3. It is reserved for the case
    where the verifier must re-read facts.
  - PLAN §8 changes to: "`fns prove` with the verifier in its own process,
    holding no test-identity or executor credential".
  - Defence in depth: `verifier_env` also sets `AZURE_CONFIG_DIR` to a new empty
    temp directory. Today it scrubs only `AZURE_*` and similar variables, and the
    Azure CLI keeps its token cache on disk (`~/.azure`), so a verifier that
    imported `azure.identity` would still find the agent's session. A test pins
    this.
- **(B)** The verifier signs in as `id-verifier` and re-reads the facts the
  assertions rest on, such as the agent's role assignments, to catch drift
  between the probes and the verification. This needs gated Azure calls from
  `fns.verify`, which breaks E6 and the import boundary. It belongs with `molt`,
  not M3.

## 5. Sigstore in CI via OIDC (P5.4, decision V3)

The keyless signing code exists (`sign_sigstore`, `verify_envelope`). It has
never run.

- **Workflow.** A new `.github/workflows/prove-sign.yml`, triggered on `push` to
  `main` and `workflow_dispatch`.
  - It has one job, with `permissions: { contents: read, id-token: write }` on
    that job only.
  - Actions are pinned by SHA, as in `ci.yml`. It installs with
    `uv sync --locked --extra sigstore`.
- **The job.** It replays `fixtures/lab-run-3` through scout, runs `fns prove` with
  the recorded `probes.json` and `--sign sigstore`, then runs
  `python -m fns.verify check --run <dir> --sigstore-identity <id> --sigstore-issuer <issuer>`,
  where:
  - the identity is
    `https://github.com/danielguillaumont/fang-and-scale/.github/workflows/prove-sign.yml@refs/heads/main`;
  - the issuer is `https://token.actions.githubusercontent.com`.

  It uploads the run directory as an artifact.
- **What the signature claims.** "This workflow, at this commit, ran the verifier
  on these frozen inputs and got this result." The inputs are the sanitized
  recording of a live run, so the statement says `mode: FIXTURE`, and the report
  says it came from a recorded live run. It does **not** claim the CI job saw
  Azure.
- **Why not sign the live bundle itself.**
  - It holds the real tenant ID, and rule 6 keeps that out of the repository.
  - Signing it in CI would mean giving GitHub Actions a federated credential for
    the assumed-compromised identity.
  - Signing it locally with Sigstore would put your personal email in a public
    certificate.

  The live bundle is signed locally with `offline-test`. The sanitized recording
  is what gets signed publicly.
- **Public log.** Rekor entries are public and permanent. They carry the signing
  certificate (repository, workflow path, ref, commit SHA) and digests.
  - Before the first production signing, P5.4 checks which fields the DSSE entry
    stores. Either way the statement holds only placeholder IDs.
  - The first runs use Sigstore **staging**, via a new
    `FNS_SIGSTORE_INSTANCE=staging|production`. Production starts only after a
    staging bundle verifies.
- **Tests.** Offline, they cover:
  - the workflow's permissions: `id-token: write` only on that job, never at the
    top level, and never on `pull_request`;
  - that the job's identity string matches the workflow path.

  Sigstore itself runs only in CI (E5).

## 6. Recording the run

- **`fns prove --live --record fixtures/lab-run-3`** writes the observations as
  `probes.json`, in the existing `MockResults` format, sanitized:
  - request IDs become placeholders;
  - resource names stay (they are lab names);
  - no body is ever recorded;
  - the description says "Recorded from the lab on <date>, sanitized", not
    "hand-written".
- **The scout half** comes from the fresh scout recording of the same run
  (`fns scout --record fixtures/lab-run-3`). Then `test_no_real_ids` runs, and the
  same `_idmap.json` rules apply.
- **Regression test.** The replay becomes the M3 regression test, the same way
  lab-run-2 is for M2. `fns demo prove` then defaults to lab-run-3, and the README
  "Real vs. fixture" row for probes changes from "Hand-written" to "Live".

## 7. What changes in the repository and the lab

| Where | Change |
| --- | --- |
| `fns.models.operations`, `fns.scope.gate`, `fns.scope.targets` | data-plane grammar and checks; principal pinning for `prove` |
| `fns.scope.credentials`, `fns.adapters.azure.http` | `kv` and `blob` tokens, `oid`; the `GET` and `HEAD` data-plane transport |
| `fns.probes.data_read` | the live `DataReadProbe`, with the outcome rule of section 1 |
| `fns.prove`, `fns.cli` | `--live`, `--record`; `AZURE_CONFIG_DIR` in `verifier_env` |
| `fns.verify.signing` | the staging or production switch |
| `lab/scope.lab.yaml.tftpl`, `lab/scope.tf` | the `prove:` block, built from resource names |
| `.github/workflows/prove-sign.yml` | new, with OIDC on one job |
| `docs/runbooks/m3-live-run.md` | from the draft below |
| Entra, Azure | **nothing permanent.** Two temporary certificates, each removed in the runbook |

## 8. Build order (offline first, one PR each)

1. **Scope gate.** Negative tests first, then the grammar, checks and principal
   pinning, plus the DECISIONS rows for V2, V4 and V5. Plan-first: I show the
   diff plan before coding.
2. **Probes and CLI.** Tokens, transport, `DataReadProbe`, `--live` and
   `--record`, all tested with a mocked transport. It also adds the
   `AZURE_CONFIG_DIR` scrub (V1).
3. **Lab scope.** The `prove:` block in the template, checked with
   `terraform validate` and the scope tests.
4. **Sigstore workflow, on staging.** It signs the existing lab-run-2 replay
   (hand-written probes, clearly labelled) to prove the pipeline. This is the
   first network contact with Sigstore, so it needs your go-ahead.
5. **The runbook.** Then you run it.
6. **lab-run-3.** The recording, regression test and README, then production
   signing and the `m3` tag.

## 9. Decisions in detail

- **V1.** See section 4. Approving it changes the gate wording in PLAN §8.
- **V2.** `HEAD` and `GET` on a blob both need
  `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`. So a
  `HEAD` denial or success is the same authorization answer, without moving any
  data. If the run shows a difference (unlikely), it is a finding, and we switch
  to `GET` with a 1-byte range.
- **V3.** See section 5. The alternative is no public signing until there is a
  tenant-free statement format. That only delays the gate.
- **V4.** Without principal pinning, a `prove` run signed in as the wrong identity
  (the admin, or the scout) would probe successfully, and the results would be
  attributed to the agent. Pinning makes that exit 4 instead.
- **V5.** Only authorization codes count as a denial. Firewall and network
  denials would make a `pass` depend on where the probe runs.
- **V6.** The alternative is no `secrets/get` data probe, with rung 2 only for
  that item. The item fails anyway on the unhardened lab, so dropping the probe
  costs nothing now. It does cost the observed denial that a `pass` needs after
  M4 hardening.

## 10. Draft runbook (superseded by `docs/runbooks/m3-live-run.md`)

The commands are Windows PowerShell, from the repository root. Use the lab from
M1 and M2, which stays up. **Do not run this until PRs 1 to 4 are merged and you
have approved V1 to V6.**

### What this run changes

| Where | Change |
| --- | --- |
| `scope.lab.yaml` (local, gitignored) | re-rendered with a `prove:` block (5 operations) |
| Entra (temporary) | a certificate on `sp-fns-scout` (2 days; deleted in step 4) |
| Entra (temporary) | a certificate on `sp-billing-agent` (1 day; deleted in step 6) |
| Azure | nothing. The probes are `GET` and `HEAD` only |

### 1. Update and check

```powershell
git switch main; git pull
uv sync --all-groups
uv run poe check
```

### 2. Re-render the scope (you approve the apply)

```powershell
az login --tenant <TENANT_ID>
az account set --subscription <SUBSCRIPTION_ID>
uv run poe lab-check
uv run poe lab-up
```

Expected plan: **1 to add, 0 to change, 1 to destroy**, `local_file.scope` only.
If it shows anything else, type `no` and send the plan.

The scope expires 2026-12-03. If that date has passed, also run
`terraform -chdir=lab apply -replace=time_offset.scope_expiry`.

```powershell
uv run fns scope check scope.lab.yaml    # not expired; the table lists 17 scout and 5 prove operations
```

### 3. Fresh scout as `sp-fns-scout`, recorded

Use M2 runbook step 3 to sign in as the scout, then:

```powershell
uv run fns scout --scope scope.lab.yaml --record fixtures/lab-run-3
$snap = (Get-ChildItem .fns\snapshots\*.LIVE.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

Expected: the same 12 collectors as in M2, with `pim.eligibility` `not-applicable`.

### 4. Remove the scout certificate

M2 runbook step 7: delete it, remove the PEM, and sign back in as yourself.

### 5. Sign in as `sp-billing-agent` and run the probes

```powershell
$tenant = az account show --query tenantId -o tsv
$agentId = az ad app list --display-name sp-billing-agent --query "[0].appId" -o tsv
$end = (Get-Date).AddDays(1).ToString("yyyy-MM-dd")
$cred = az ad app credential reset --id $agentId --create-cert --end-date $end --append | ConvertFrom-Json
Start-Sleep -Seconds 180
az login --service-principal --username $agentId --certificate $cred.fileWithCertAndPrivateKey --tenant $tenant
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table   # type: servicePrincipal, user: $agentId

uv run fns prove --contract contracts\lab\billing-agent.fns.yaml --snapshot $snap --live --record fixtures/lab-run-3 --identity local-verifier
$LASTEXITCODE                                    # expected: 1
```

Run nothing else in this session.

- Exit 4 with `principal-not-allowed` means the wrong identity is signed in.
  Stop and check `az account show`.
- Expected: the table in section 1. The output says `passed: 1  critical
  reachable: 11  still-do failed: 0  inconclusive: 1`, `signer: offline-test`
  and `TEST SIGNATURE`.
- The journal shows 13 `probe:` steps and no gate denial.

### 6. Remove the agent certificate at once

```powershell
az login --tenant $tenant
az ad app credential list --id $agentId --cert --query "[].{keyId:keyId, end:endDateTime}" -o table
az ad app credential delete --id $agentId --key-id <keyId> --cert
Remove-Item $cred.fileWithCertAndPrivateKey
az ad app credential list --id $agentId --cert -o table   # should be empty
az logout
```

### 7. Check the recording

```powershell
uv run pytest tests/fixtures/test_no_real_ids.py -q
git status --short fixtures/lab-run-3          # _idmap.json must NOT be listed
Copy-Item contracts\lab\billing-agent.fns.yaml fixtures\lab-run-3\contract.fns.yaml
uv run fns demo prove --fixture fixtures/lab-run-3
$LASTEXITCODE                                    # expected: 1, same verdicts as step 5
```

### 8. Report back

Send the following:

- **Step 2:** the plan line.
- **Step 5:**
  - the Findings block and summary line;
  - for each of the 13 probes, its outcome, HTTP status and error code;
  - any probe that came back `unknown`.
- **Step 7:** the test result.
- Anything that differs from section 1.

Every error code that differs from the documented one is a FINDINGS entry.

After that: the lab-run-3 PR, the `prove-sign` run on `main` (staging, then
production), `python -m fns.verify check` with the Sigstore identity, and the
`m3` tag.

### Troubleshooting

- **`AADSTS700027` on the agent sign-in:** wait 3 more minutes and repeat only the
  `az login --service-principal` line (FINDINGS, 2026-11-26).
- **Data read `unknown` with `401`:** the token audience is wrong, or the
  token is missing. Report the error code, and do not retry with another identity.
- **`ForbiddenByFirewall` or `AuthorizationFailure`:** a network rule is in the
  way. The lab sets none, so report it. The probe stays `unknown` by design (V5).
- **Invoices `HEAD` returns `403`:** Blob Data Contributor did not reach the data
  plane, or it was removed. That is a `must_still_do` failure: report it, and do
  not change RBAC.
