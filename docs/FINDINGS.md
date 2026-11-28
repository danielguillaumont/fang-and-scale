# Findings: Microsoft API behaviour vs documentation

Record every case where ARM or Graph behaves differently than documented: the
request (sanitized), the response, the date, and what the code does about it.

| Date | API | Request | Documented | Observed | Handling |
| --- | --- | --- | --- | --- | --- |
| 2026-11-26 | ARM (Azure Policy) | `terraform apply` creating `rg-fns-lab` with `location = "eastus"` on an Azure for Students subscription | Any public region can be used for a resource group | Denied by the built-in assignment "Allowed resource deployment regions". Allowed on this subscription: `belgiumcentral`, `northcentralus`, `norwayeast`, `westus`, `canadacentral`. List with `az policy assignment list --query "[].{name:displayName, allowed:parameters.listOfAllowedLocations.value}"` | `location` is now a required Terraform variable with no default; runbook step 3 lists the allowed regions first, and step 4 has a troubleshooting entry |
| 2026-11-26 | ARM (`Microsoft.KeyVault/vaults` PUT, `canadacentral`) | azurerm 5.15.0 creating `kv-crown-<suffix>`, then polling the long-running operation | Polling returns the operation status until the vault is provisioned | A polling GET returned **404** and Terraform failed, but the vault had been created. It was then missing from state, and a re-apply failed because the name was taken | Recovered with `terraform import azurerm_key_vault.crown_jewels <vault id>`, then apply. Runbook step 4, "Troubleshooting". Not retried automatically: the tool never applies Terraform |
| 2026-11-26 | Entra ID token endpoint (client credentials, certificate) | `az login --service-principal --certificate <pem>` right after `az ad app credential reset --create-cert --append` on `sp-fns-scout` | A new credential is usable once the reset call returns | First sign-in failed with `AADSTS700027` (invalid signature on the client assertion); the same command worked about 3 minutes later with no change | Runbook step 5: wait 3 minutes and retry the login; do not create a second certificate. Live collectors use the existing CLI session, so no code change |
| 2026-11-26 | Graph v1.0 `roleManagement/directory/roleEligibilitySchedules` (app-only, `sp-fns-scout`, `RoleManagement.Read.Directory`) | `GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,roleDefinitionId,directoryScopeId` in an Entra ID Free tenant | PIM needs Entra ID P2 or ID Governance. The response to a tenant without them was unknown to us; the tests used `AadPremiumLicenseRequired` only as an illustration | **`400`**, not `403` or an empty list: `{"error": {"code": "AadPremiumLicenseRequired", "message": "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.", "innerError": {"date": "2026-11-26T18:07:28", "request-id": "<placeholder>", "client-request-id": "<placeholder>"}}}` | The collector records the status and error code (`http-400 AadPremiumLicenseRequired`) as evidence and never keys on the code or the message: any failed listing counts the same, and the licence check decides. Recorded in `fixtures/lab-run-2` |
| 2026-11-26 | ARM `Microsoft.Authorization/roleEligibilitySchedules` (`api-version=2020-10-01`, Reader on the subscription) | `GET https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01` in the same tenant | As above | **The same status and code from a second API**, with a different message: `400` `{"error": {"code": "AadPremiumLicenseRequired", "message": "The tenant needs to have Microsoft Entra Permissions Management or <GUID> or Microsoft Entra ID P2 or Microsoft Entra ID Governance license."}}`. ARM accepts more licences than Graph names, and it names one of them only by a GUID. The sanitizer replaced that GUID with a placeholder (`...-000000001049`), which appears nowhere else in the recording, so it is not the tenant, the subscription or any object in it. No `innerError` | Handled the same way as Graph. **Resolved 2026-11-26:** the old match (one P2 plan ID, plus SKU or plan names containing `P2` or `GOVERNANCE`) did not know Permissions Management or the GUID-named licence. A tenant with only one of those could have been reported `not-applicable`. The matcher now uses service plan IDs only. `not-applicable` needs every plan of every live SKU to be on `graph.PIM_FREE_PLAN_IDS`, a list of IDs known not to carry PIM. That list starts empty, so any unknown SKU or plan keeps `pim-eligibility` not collected and its findings inconclusive. This tenant (0 SKUs) is unchanged |
| 2026-11-26 | Graph v1.0 `subscribedSkus` (app-only, `sp-fns-scout`) | `GET https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,servicePlans` in the same tenant | Lists the tenant's commercial subscriptions | `200` with `"value": []`: an Entra ID Free tenant (here on an Azure for Students subscription) has **no subscribed SKUs at all**, not even a free one | **0 SKUs is a valid not-applicable signal.** A successful, empty answer is positive evidence that no licence carries PIM. It is different from a failed call, which leaves `pim-eligibility` not collected. The evidence line reads `GET /subscribedSkus -> ok: 0 SKU(s) [none]; plans that may carry PIM: none` |
| 2026-11-27 | ARM `microsoft.aadiam/diagnosticSettings` (`api-version=2017-04-01-preview`) | `PUT https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/fns-logcheck` with `AuditLogs` and `ServicePrincipalSignInLogs` enabled, to a Log Analytics workspace, in an **Entra ID Free** tenant (0 subscribed SKUs, no P1 or P2, no trial) | Microsoft's two current pages, "Integrate Microsoft Entra logs with Azure Monitor logs" (updated 2026-06-15) and "Configure Microsoft Entra diagnostic settings" (updated 2026-02-26), list no licence. Older guidance, as the CIS benchmark quotes it, says "To export sign-in data, your organization needs an Azure AD P1 or P2 license" | **Accepted, both categories.** Rows arrived in both tables: `AuditLogs` 6, `AADServicePrincipalSignInLogs` 1. The current pages are right for this tenant; the older P1/P2 statement does not hold here | D1 stands: no trial. S4 can get a sign-in rule. Section "M4 log path check" below |
| 2026-11-27 | `AADServicePrincipalSignInLogs` (`ClientCredentialType`) | `az login --service-principal --certificate <pem>` as `sp-fns-scout`, then the runbook's `qSignIn` query | Our runbook expected `Certificate` for a certificate sign-in | **`clientAssertion`.** The CLI signs a JWT client assertion with the certificate, and the log names the assertion, not the certificate | Runbook and rules match `clientAssertion`. A rule must not key on `Certificate` to find certificate sign-ins |
| 2026-11-27 | `AuditLogs` ("Update application – Certificates and secrets management") | Adding a certificate to `sp-fns-scout` (`az ad app credential reset --create-cert --append`), then deleting it (`az ad app credential delete`) | Our runbook said the delete would not match the add's filter | **Both match.** Adding and deleting a key log the **same** `OperationName`, both `success`, both initiated by a user. What tells them apart is `TargetResources[].modifiedProperties`: the key list before the change (`oldValue`) and after it (`newValue`) | The runbook query and the credential rules compare the number of keys before and after (`KeyDescription`), and never decide on `OperationName` alone. **Not yet confirmed live:** the property name and its JSON shape are from Microsoft's audit log examples, not from this run's rows. The runbook prints the property names if the comparison finds nothing |

## M4 log path check (2026-11-27)

Run from `docs/runbooks/m4-log-path-check.md` on a fresh lab build, on the Entra
ID Free tenant (no P1 or P2 licence, no trial started). Decision D1 stands.

- **Diagnostic setting:** the `PUT` accepted both `AuditLogs` and
  `ServicePrincipalSignInLogs`.
- **Rows:** `AuditLogs` 6, `AADServicePrincipalSignInLogs` 1 (the `qTables`
  query, from the setting's creation on).
- **`qAudit`:** 2 rows, both "Update application – Certificates and secrets
  management", `success`, `By` = `user`, target `sp-fns-scout`: the add at
  05:41:07Z and the delete at 05:45:14Z. The runbook expected only the add.
- **`qSignIn`:** `ResultType` 0, `ClientCredentialType` = `clientAssertion` (the
  runbook expected `Certificate`), resource Azure Resource Manager.
- **Latency:** about 10 to 15 minutes from the event to the row.
- **Cleanup:** the certificate, the diagnostic setting, the workspace and its
  resource group were deleted, then `lab-down`.

Three runbook problems, now fixed in the runbook:

- `az group show --ids <resource group id>` failed. The runbook uses
  `az group show -n rg-fns-lab`.
- The expected values above (`clientAssertion`; the add and the delete both
  match, told apart by `modifiedProperties`).
- If `uv run poe lab-down` (or `lab-up`) is pasted together with the lines
  after it, Terraform reads the next pasted line as the answer to its `yes`
  prompt. Every command that prompts now sits alone in its own block, with a
  warning.

Sources: the two Microsoft pages and the CIS quote are linked in
`docs/milestones/M4-plan.md`, "Sources".

## M3 live run (2026-11-26)

Run from `docs/runbooks/m3-live-run.md`. The scout ran as `sp-fns-scout`, and the
probes ran as `sp-billing-agent`, the identity the contract assumes is
compromised.

- **Scout:** digest
  `sha256:68a0208d9c91330bd187a1f4f9b284d801e7fa7c224006edb9399bf2a179b129`,
  identical to M2, after 34 gated calls. The lab did not change between the runs.
- **`fns prove --live`:** passed 1, critical reachable 11, still-do failed 0,
  inconclusive 1, exit 1. The live bundle is `sha256:4b537ab6…`, signed with the
  offline test key.
  - Invoices `blob/read` passed, observed and verified. This is M3's first
    verdict backed by an observed probe.
  - Key Vault `secrets/get` and `secrets/list`, and payroll `blob/read`, were
    denied when probed. They still fail, because escalation paths remain:
    Contributor lists `vaults/write` and `listKeys`.
- **The data-plane answers matched the documentation exactly.** There is no new
  API row in the table above.
  - Key Vault `GET` of the secret and of the list both returned `403`
    `Forbidden`, inner code `ForbiddenByRbac`.
  - Blob `HEAD` on payroll returned `403`, `x-ms-error-code:
    AuthorizationPermissionMismatch`. On invoices it returned `200`.
  - The 9 `permissions` reads all returned `200` and listed exactly the actions
    the hand-written `probes.json` predicted.

  The V6 pre-flight (the ARM metadata read of the secret) saw the tag
  `fns-data = synthetic`, so the Key Vault `GET` was sent. No secret value was
  returned, read or stored.
- **Recorded as `fixtures/lab-run-3`.**
  - Its scout half replays to the M2 digest,
    `da85272752f74a1bc99a966743abe0657f226f28aede542b9dfe75ec61ab549c`.
  - Its `probes.json` holds 13 results, all `allowed` or `denied`, none omitted.
  - `test_no_real_ids`: 25 passed. `_idmap.json` is ignored.
  - The replay (`fns demo prove --fixture fixtures/lab-run-3`) gives the same
    verdicts, exit 1, bundle `sha256:ab673d8e…`. It differs from the live
    bundle by design. Since denied probes are attached to their findings as
    context (below), the pinned replay digest is `sha256:913a079f…`, with the
    same verdicts.
- **Two Windows hiccups in the runbook, both fixed in it.** Neither is an Azure
  API behaviour.
  - In PowerShell, `terraform apply -replace=time_offset.scope_expiry` has to be
    quoted (`"-replace=time_offset.scope_expiry"`); unquoted, it did not reach
    Terraform intact, most likely because PowerShell parses the `-name=a.b` form
    itself. All runbooks and `lab/scope.tf` now quote it.
  - `Remove-Item -Recurse -Force` on a temporary `AZURE_CONFIG_DIR` failed once,
    on a file Windows still held after `az logout`, and worked 10 s later. The
    runbook now retries up to 5 times, 3 s apart, and then checks the folder is
    gone.
- **The M3 regression test is `tests/fixtures/test_lab_run_3.py`:** the recorded
  probe outcomes, every verdict and coverage state, the summary, the observed
  pass, and the replay digest.
- **Cleanup:** the agent's and the scout's certificates were deleted and
  verified, and the temporary CLI profiles were removed.

## Live and replay bundle digests differ (2026-11-26)

The M3 live bundle is `sha256:4b537ab6…`. Its replay,
`fns demo prove --fixture fixtures/lab-run-3`, gives `sha256:ab673d8e…`.
**This is by design, not a bug: no verdict content differs.**

I compared the two bundles and their `assertions.json` locally, after mapping
the live run's real IDs to the recording's placeholders through `_idmap.json`.
Neither the live run directory nor the mapping is committed. Ignoring list
order, these are identical:

- all 13 finding IDs;
- every verdict, coverage state, gap and reason;
- every evidence rung, outcome and source;
- the summary, the contract digest and the tenant.

What differs, and why:

| Field | Why it differs |
| --- | --- |
| `mode` | `LIVE` versus `FIXTURE` |
| `snapshot_digest` (and `report_digest`, `assertions_digest`) | The live snapshot holds the real tenant, subscription and object IDs; the recording holds placeholders. This is the same reason the M1 and M2 scout digests differ from their replays |
| probe IDs, artifact `sha256`, list order | A probe ID is `sha256(finding, kind, target, action)`, and the target is the full ARM path, which contains the subscription GUID. So every probe ID differs. Artifacts hash their probe ID, and lists sorted by probe ID come out in a different order |
| `run_id`, `generated_at`, `observed_at` | The run ID hashes the report digest and the freeze time. The live run freezes at the time it runs; the replay freezes at the recording's `recorded_at` |
| `verifier` | `fns.verify as local-verifier` (the runbook's `--identity`) versus `fns.verify as fixture-replay` |
| two evidence `notes` | Live notes end with "(same request as probe …, sent once)" where one request answered two findings. The recording keeps the answer, not the sharing, so the replay has no such note |

The replay digest is deterministic: it matched the golden and the replay run
right after the live run. (The golden is now `913a079f…`, after context evidence
was added; see the next section.) Two tests guard the
equivalence. `tests/prove/test_live_probes.py::test_live_and_replay_bundles_agree_on_every_verdict`
runs the live pipeline against lab-shaped answers, records it, replays the
recording through the real verifier, and requires the same findings content.
`tests/fixtures/test_lab_run_3.py` pins the M3 verdicts.

A digest that both sides could compare would have to leave out the mode, IDs and
timestamps. Nothing needs one yet; if the verifier gains one, it should hash
exactly the identical fields listed above.

## Denied probes are attached to their findings (2026-11-26)

Decision 1 on the M3 summary. Before this change, the M3 bundle linked three
findings only to the evidence that kept them failing: Key Vault `secrets/get`,
`secrets/list` and payroll `blob/read`. Their reason said "denied when probed",
but the observed `403` was only in the run's artifacts.

Every probe result that came back `allowed` or `denied` is now in its finding.
Results the verdict rests on are supporting evidence, as before. The rest carry
`role: context`. Coverage, the verdict checks and the gap checks read
supporting evidence only, so context cannot raise `evaluated-only` to
`verified`, or back a pass.

`tests/golden/prove-verdicts.json` was recorded from all four prove goldens
before the change. `tests/prove/test_verdict_baseline.py` requires the same
verdict, coverage, gap, reasons, supporting evidence and summary for every
finding; evidence lists may only grow, with context. All four digests changed,
for these entries only:

| Golden | Findings with context | Added |
| --- | --- | --- |
| `demo-prove` | Key Vault `secrets/get` | observed denied, evaluated denied |
| `lab-run-1-prove`, `lab-run-2-prove`, `lab-run-3-prove` | Key Vault `secrets/get` and `secrets/list`, payroll `blob/read`: each gets its observed `403` and the evaluated denial of the same action. Invoices `blob/read` (still-do, pass) and `blob/write` (still-do, inconclusive) each get the allowed `listKeys` hop | 3 observed denied, 3 evaluated denied, 2 evaluated allowed |

## M2 live run (2026-11-26)

Run from `docs/runbooks/m2-live-run.md`. Every result matched the runbook tables.

- **Terraform:** 3 to add, 0 to change, 1 to destroy (scope file, lab contract,
  `LicenseAssignment.Read.All`). The tenant has 0 SKUs (Entra ID Free).
- **Scout as `sp-fns-scout`, twice:** identical digests,
  `sha256:68a0208d9c91330bd187a1f4f9b284d801e7fa7c224006edb9399bf2a179b129`.
  There are 12 collectors. 11 are `complete`, including `arm.resource-settings` with
  3 items. `pim.eligibility` is `not-applicable`, with the three responses above as
  evidence.
- **Recorded as `fixtures/lab-run-2`,** with the contract `lab/contract.tf`
  rendered (names only). `test_no_real_ids` passed, and `_idmap.json` is ignored.
  The replay digest is
  `da85272752f74a1bc99a966743abe0657f226f28aede542b9dfe75ec61ab549c`. It differs
  from the live digest because the IDs are placeholders and the mode is `FIXTURE`.
  It is pinned in `tests/golden/lab-run-2.digest`.
- **`fns contain`, live:** critical reachable 11/0, inconclusive 2/2, exit 1. The
  fixture replay gives the same result. `stpayroll` `blob/read` now fails without
  a "not collected" assumption, because shared-key access was collected (C1).
- **`fns mutate --harden`, live:** 6/8, exit 0 with `--max-survivors 2`. The
  survivors are exactly `app-owner:id-verifier` and `app-owner:sp-fns-scout`. The
  hardened baseline has 0 failing and 13 inconclusive findings.
- **The M2 C4 regression test is `tests/fixtures/test_lab_run_2.py`:** collectors,
  PIM evidence, verdicts, summary, mutation score and survivors, against
  goldens.
- **Cleanup:** the scout certificate is deleted, the PEM is removed, and
  `az logout` was run.

## First live run (2026-11-26)

- Two scouts as the lab admin gave the same digest
  (`sha256:463a3c058ef43bdabf5ea4d647c69405274c4b56b0fc628c0088b3d8e37d2c66`).
  All 10 collectors were `complete`: 210 entities, 31 edges, 28 gated calls.
- A third scout signed in as `sp-fns-scout` (Reader on the subscription;
  Application.Read.All, RoleManagement.Read.Directory, Directory.Read.All) gave
  the **same digest**, with every collector `complete`.
- The first run was recorded and sanitized as `fixtures/lab-run-1`.
  `tests/fixtures/test_no_real_ids.py` passed, and the replay digest is pinned in
  `tests/golden/lab-run-1.digest`.

## Mutation testing found a gap in our own contract (2026-11-26)

Not Microsoft behaviour, but a finding about this project's own contract, found
by `fns mutate` (M5) on `fixtures/lab-run-1`, hardened in the model.

- **First run: 5 of 8.** The seeded contract (version 1) missed three mutants:
  - `listKeys` on the invoices account. The contract simply did not forbid it.
  - The agent becoming an owner of `id-verifier`.
  - The agent becoming an owner of `sp-fns-scout`.

  Version 1 could not name one application as a target, so the contract had no
  way to say "the agent must never control the verifier". This was a gap in the
  model, not just a missing line.
- **Fix: contract version 2** (approved in the morning review).
  - `must_not_reach` can name an `application` or a `service_principal`, with
    `credentials/update` and `owners/update`.
  - The seeded contract now forbids both operations on `id-verifier` and
    `sp-fns-scout`, and `listKeys` on the invoices account.
  - A new detection rule, `object-owner-added-by-workload`, covers owner changes.
- **Second run: 6 of 8.**
  - `listKeys` on invoices is killed.
  - Every Graph-permission mutant now also fails the four new items. On the
    unhardened lab, the agent reaches both applications through the self-grant
    chain (owner adds a credential, then `AppRoleAssignment.ReadWrite.All` grants
    `Application.ReadWrite.All`).
  - The two ownership mutants still survive, for a real reason. In the hardened
    lab the agent holds neither `Application.ReadWrite.OwnedBy` nor
    `Application.ReadWrite.All`. An app-only caller cannot use an ownership
    without one of them, so ownership alone adds no reach. The model sees the
    change, and the survivor's output says "owns id-verifier but holds neither
    ... (one Graph grant away)".
- **Accepted (2026-11-26 review).** The two ownership mutants are accepted,
  explained survivors. No contract line can kill them, because ownership alone
  allows none of the forbidden operations. A check that fails on an unusable
  ownership would be a new kind of check, not a contract change. The Graph grant
  that would make the ownership usable is already caught by the three
  Graph-permission mutants.

## Research items (planned, not run)

- **R1. Does ARM authorize before it validates?** If so, a deliberately
  invalid write returns `403` when the caller is denied and `400` when it is
  allowed, which would be a non-mutating authorization probe for writes. The
  plan is in `docs/milestones/M3.md` (R1). No request has been sent; until a
  result is recorded here, writes stay at rung 2 at most (E4).

- **R2. Which pull-request subject does a federated credential need?**
  (documentation only, 2026-11-28, not run.) Microsoft Learn, "Configure an app
  to trust an external identity provider" (GitHub Actions, Azure CLI tab), gives
  the pull-request subject as `repo:<Organization/Repository>:pull-request`
  (hyphen). GitHub's OIDC reference
  (<https://docs.github.com/en/actions/reference/security/oidc>) says the token
  carries `repo:ORG-NAME/REPO-NAME:pull_request` (underscore). Subjects must match
  exactly and case-sensitively, so a credential with the hyphen may match no
  token. Handling: `fns.contain.federation` reads `pull_request` as the
  pull-request front door (high) and `pull-request` as `github-other`
  (severity unknown), never as safe. Live check LV-7.

## Open questions from Phase B

- **TODO: fill `graph.PIM_FREE_PLAN_IDS` (decision 3, 2026-11-26; owner
  decision: leave it empty for now).** It starts empty, so any tenant with a
  licence gets `pim-eligibility` not collected when an eligibility listing fails.
  Populate it **only** from Microsoft's official reference, "Product names and
  service plan identifiers for licensing" (Microsoft Learn, Entra ID, under
  enterprise users; it is also published as a CSV). Each entry needs:
  - the `servicePlanId` GUID, the `servicePlanName`, and a SKU that carries it,
    copied from that reference, which is cited with the date it was read;
  - a reason the plan cannot carry PIM. Entra ID P2, ID Governance and any plan
    that includes them never qualify;
  - a test that pins the entry (and its citation) in `tests/inventory/test_pim.py`,
    replacing `test_the_pim_free_list_starts_empty`, plus a collector test where a
    tenant with only listed plans is `not-applicable`.

  Never infer an entry from a name, and never add one from a tenant's own
  `/subscribedSkus` response.
- **Is `Directory.Read.All` needed?** Partly answered. The full set is
  sufficient, but nothing has tested whether it is minimal: the lab's owners are
  one user and three service principals, and no service principal is a member of
  a group. Next live run: apply with `scout_directory_read_all = false` and
  compare (runbook step 9, "Next live run"). Until then it stays in the default.
- **Well-known IDs** (`src/fns/fixtures/wellknown.py`). Checked against the
  tenant's responses, and kept checked by `tests/fixtures/test_lab_fixture.py`.
  Two were wrong, both my errors rather than API behaviour:
  - `APPLICATION_READWRITE_ALL` was `...-73c6d2b2e8db`; the tenant returns
    `1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9`.
  - `KEY_VAULT_SECRETS_OFFICER` (`b86a8fe4-44ce-4948-aee5-eccb2c155cd7`) was
    missing.

  The sanitizer had replaced both with placeholders in the recording. They are
  now on the allowlist and restored verbatim in `fixtures/lab-run-1`. Every other
  RBAC role, Graph app role and directory role template that appears in the lab
  matched.
- **Assignments at `/` or at management groups.** Not exercised. The lab
  subscription's listing returned only subscription and resource-group scopes.
  The handling stays as built; it is covered by unit tests only.
