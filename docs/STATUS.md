# Status

## Build session of 2026-11-27

A long offline session working through the owner's queue, one focused PR per
item. No Azure, Graph or Log Analytics call, no `az` command and no Terraform
apply or destroy is made; `uv run poe lab-check` (fmt and validate) is the only
Terraform run. To resume, read this section first.

### Latest changes

| PR | Queue item | Change | Tests after |
| --- | --- | --- | --- |
| #60 | 1 | **M4 step 1 passed; D1 stands.** FINDINGS rows and section "M4 log path check" (both categories export on Entra ID Free; `clientAssertion`; a key's add and delete share one operation name). Runbook corrections (`az group show -n rg-fns-lab`, the expected values, an audit query that tells add from delete, prompting commands pasted alone). M4-plan step 1 marked passed | 1404 |
| #61 | 2 (part 1) | **Detection rules tested against sample rows.** `fns.harden.kql`, a small KQL evaluator that refuses anything it doesn't model; `detections/samples/<id>.yaml` for every rule, each with rows that must alert and rows that must not; `fns detections check` runs them. `app-credential-added-by-workload` no longer fires on a key delete. New rule `workload-sign-in-with-secret` for S4. Mutation tests show the samples catch the delete, a certificate sign-in, and an ignored failure | 1471 |
| #62 | 2 (part 2) | **`lab/monitoring.tf` (D2)**, off by default (`enable_monitoring`). Workspace with Sentinel, Activity Log, Key Vault, blob and Entra diagnostic settings, and one scheduled rule per `detections/` file from the generated `lab/detections.json` (`fns detections export --terraform`, with `--check`). 18 more resources when on. `lab-check` passes; tests check every rule's table is fed, the rules are exactly `detections/`, and nothing deploys by default | 1482 |
| #63 | 3 | **Lab group (D3):** `lab/groups.tf`, `grp-fns-billing`, a security group with `sp-billing-agent` as its only member, no roles, not role-assignable. The scout already reads `memberOf`, and the model already has groups; new tests check the lab-shaped response becomes one edge and that a group with no roles changes no verdict. The default lab plan is now **37 to add** (39 with the budget) | 1487 |
| #64 | 4 (part 1) | **Strike engine core (`fns.strike`), no command yet.** Plans and their sha256, approval that admits one armed request at a time, journaled intent and result for every write (new append-only `strike_events` table, no bodies or secrets), every undo in a `finally` in reverse order, verification by the scout, journal-driven cleanup after a crash. S1 to S3, and D-1 to D-5 expecting denials. Secrets stripped inside the transport. Tested against a fake tenant only: faults at every step, a crash at every send, tampered hashes, a dropped undo caught by verification, and a fuzz test over fault schedules | 1591 |

Tests at the start of the session: 1402 passed, 1 skipped (the Action's bash script, Linux only). Counts below are passed tests on Windows.

### Queue position

1. ~~Log path check results~~ (#60)
2. ~~Detection rules~~: sample-row tests (#61), `lab/monitoring.tf` (#62)
3. ~~Lab group (D3)~~ (#63)
4. Strike engine: ~~core~~ (#64). **Next:** S4 (escalated sign-in, gate rule), then `fns strike plan/run/cleanup` with recorded-fixture replay, then D-1 to D-5 as verdict evidence (approved with the guardrail)
5. M4 live runbook
6. Report and UX
7. v0.1 release prep (no tag, no publish)
8. ARCHITECTURE and THREAT-MODEL
9. M6 groundwork (read-only MCP server)
10. Hardening and quality

### Needs Daniel

Nothing yet.

### Pending review

Approved on 2026-11-27 (marked in `docs/DECISIONS.md`): the KQL evaluator, the
two rule choices, the 1 GB cap, both ID kinds monitored, the plan expiry and
pre-state re-read, journal-driven cleanup, the `strike_events` table, and D-1 to
D-5 as verdict evidence with the "never looser" guardrail.

Still pending (strike engine, #64; not in the approved list):

- a transport error counts as "sent", so the undo runs (S1 regenerates both keys);
- a lost `addPassword` answer is undone by the run's credential name;
- an after-harden attempt that succeeds is undone at once;
- `fns strike` exit codes 0 / 1 / 4 / 5, with 5 (verification failed) first.

# Status after the M3 live run (2026-11-26)

## Milestone results

| Milestone | Live run | Result | Regression test |
| --- | --- | --- | --- |
| M1 Scout | 2026-11-26 | scout as the admin, then as `sp-fns-scout` | `fixtures/lab-run-1` |
| M2 Contain | 2026-11-26 | critical reachable 11, inconclusive 2, exit 1; mutation 6/8 with the two accepted app-owner survivors | `tests/fixtures/test_lab_run_2.py` |
| M3 Prove | 2026-11-26, probes as `sp-billing-agent` | passed 1 (invoices `blob/read`, observed and verified), critical reachable 11, still-do failed 0, inconclusive 1, exit 1. The Key Vault and payroll reads were denied when probed and still fail: escalation paths remain | `tests/fixtures/test_lab_run_3.py` |


## The repository is public (2026-11-26)

The owner made the repository public, turned on secret scanning with push
protection, Dependabot alerts and security updates, private vulnerability
reporting, and branch protection on `main` (no force push, no deletion, no
required checks yet). The lab is torn down, and new commits use the noreply
address. Details and the settings as read back from the API:
`docs/PUBLIC-READINESS.md`, "Status: PUBLIC".

| PR | Change |
| --- | --- |
| #49 | **V3 done:** `prove-sign` signs on Sigstore **production** on every push to `main` (first entry: Rekor log index 4138528019), and on staging for pull requests from branches of this repository. Production is refused in code anywhere else. README: "Verify a signed result" |
| #50 | CodeQL can be started by hand (`workflow_dispatch`); it runs green on `main` |
| #51 | A Sigstore verification failure (for example a wrong identity) exits 5 with `EVIDENCE INVALID`, not a traceback |
| this PR | PUBLIC-READINESS status, this section, README "Project status" |

## After the M3 live run

Each item from the M3 run report got its own branch and PR. CI passed on ubuntu
and windows, and all six are merged to `main`. `m3` is tagged on `main`. No Azure
call, `az` command or Terraform apply was made after the run.

| PR | Item | Change |
| --- | --- | --- |
| #36 | 1 | `fixtures/lab-run-3` is committed as the M3 regression test (`tests/fixtures/test_lab_run_3.py`): the recorded probe outcomes, every verdict and coverage state, the summary, the observed pass and the replay digest. Every `fns demo` command, and `prove-sign`, default to it. README, STATUS and FINDINGS record the run |
| #37 | 2 | `probes.json` carries `source`. The replay banner says "recorded live probe results" for lab-run-3, and "hand-written probe results" for lab-run-1, lab-run-2 and `demo-scout` |
| #38 | 3 | FINDINGS, "Live and replay bundle digests differ": **not a bug**. Verdicts, coverage, reasons and evidence rungs are identical. The digests differ by mode, real vs placeholder IDs (which also change every probe ID, since it hashes the full ARM path), run ID and timestamps, the verifier label, and a live-only "sent once" note. A new test replays a live recording and requires the same findings |
| #39 | 4 | The PIM licence matcher uses service plan IDs only. `not-applicable` needs every plan of every live SKU on `graph.PIM_FREE_PLAN_IDS`, which starts empty; any unknown SKU or plan keeps the surface not collected, so findings stay inconclusive. Resolves the M2 FINDINGS open item. No digest changed |
| #40 | 6 | Runbooks quote `"-replace=time_offset.scope_expiry"` for PowerShell, and retry removing the temporary `AZURE_CONFIG_DIR` up to 5 times |
| #41 | 5 | `sigstore` stays an extra. `poe setup`, CI and the runbook sync with `--all-groups --all-extras`. Both sigstore tests now run in CI (1152 passed, 0 skipped) |

Tests: 1128 before these PRs, 1152 after.

## Decisions waiting for you

1. **Done (approved 2026-11-26): denied probes are now linked to their finding as context.** See FINDINGS, "Denied probes are attached to their findings". The text below is the original question.
   **Denied probes were not linked to their finding.** For Key Vault
   `secrets/get` and `secrets/list` and payroll `blob/read`, the finding's reason
   says "the operation itself was denied when probed, but escalation paths
   remain". Its evidence lists only the modeled path and the *allowed* hop.
   The observed denial is in the bundle's artifacts, but not in the finding
   (`src/fns/verify/verdict.py`, the unrefuted `must_not_reach` branch).
   Linking it is more honest, but it changes the evidence model and every
   prove golden, so it needs a plan and your approval. The verdicts would not
   change.
2. **Decided 2026-11-26: stays refused until the repository is public (V3). Done after it went public: production signing on `main` (#49).** The text below is the original question.
   **Sigstore production (Rekor).** Still refused in code
   (`PRODUCTION_APPROVED = False`). `prove-sign` signs `fixtures/lab-run-3` on
   staging on every push to `main`.
3. **Decided 2026-11-26: stays empty for now.** FINDINGS has the TODO for filling it from Microsoft's licensing reference. The text below is the original question.
   **`PIM_FREE_PLAN_IDS` is empty.** Until it holds verified plan IDs, any tenant
   with licences gets `pim-eligibility` not collected when an eligibility listing
   fails, and its findings stay inconclusive. Filling it means checking IDs
   against Microsoft's licensing list. The lab is unaffected.

## Public-readiness audit

See `docs/PUBLIC-READINESS.md` (#43 to #48): findings, fixes, the GitHub
settings to turn on, four owner decisions, and the recommendation.

## Next

M4 (Harden + detect) is built offline. Its live plan is
`docs/milestones/M4-plan.md`: lab rebuild, the `Directory.Read.All` and
custom-role scout tests, logging and record mode, the four strikes with their
detection results, harden and prove the fix, trial costs against the $100
credit, and who does what. D1 to D8 were approved on 2026-11-26. D1 changed:
step 1 is now a live check of whether Entra audit and service principal sign-in
logs reach Log Analytics on Entra ID Free. The current Microsoft page lists no
licence, older guidance says P1 or P2. D7 is `lab/budget.tf`, which is opt-in,
because Cost Management does not support Azure for Students.

The strike plan (D4, plan only) is `docs/milestones/M4-strikes-plan.md`. It lists
every request in order with its undo, the stop line (no directory role is ever
assigned), the write gate limited to lab objects, with fuzz tests, the journal,
cleanup and emergency steps, and decisions SD1 to SD5. No strike code exists.

SD1 to SD5 were approved on 2026-11-26. SD2 came with a condition: the marker role
lives only on a lab-created app, and the gate enforces it. SD3 is a deliberate
limit, explained in the README. Build step 1, the write gate, is built and tested
offline, with nothing calling it. The places where the build differs from the
plan are in the strike plan's "Build status".

**The log path check passed on 2026-11-27** (`docs/runbooks/m4-log-path-check.md`):
both Entra log categories reach Log Analytics on Entra ID Free, so D1 stands and
no trial is needed. See FINDINGS, "M4 log path check".

## The morning review (before the M2 and M3 runs)

Every item from the morning review of `docs/OVERNIGHT.md` is done. Each one got
its own branch and PR. CI passed on ubuntu and windows on the first run every
time, and all of them are merged to `main`. No Azure call, `az` command or
Terraform apply was made. Everything was tested with fixtures and mocks.

### What changed

| PR | Review item | Change |
| --- | --- | --- |
| #18 | approvals, M3/M4, 7, 10, 12 | Overnight decisions are marked approved or reviewed in `docs/DECISIONS.md`, and M3 and M4 are approved. M3 E1 is rewritten for the PIM collector. M3 also gets research item R1 (does ARM authorize before it validates?), plan only, also listed in `docs/FINDINGS.md`. M4 gets the four non-destructive lab strikes (H6) and "narrow to a custom role" on its roadmap (H1). `docs/PLAN.md` is updated |
| #19 | 18 | Exit codes match the README for every command and for the GitHub Action: 0 within budget, 1 contract or check failed, 2 usage or invalid input (missing or invalid contract, scope or input files, and internal errors), 3 inconclusive over budget, 4 scope denied, 5 evidence invalid. `tests/test_exit_codes.py` has a test per code, including 21 invalid-input cases for code 2. The semantics did not change; the README now spells out which checks exit 1 |
| #20 | demo default | `fns demo scout`, `contain`, `prove`, `report` and `mutate` replay the recorded `fixtures/lab-run-1` by default. Outside a checkout they exit 2 with a hint. `demo-scout` stays for tests |
| #21 | 16 | Cytoscape 3.30.2 is vendored in `src/fns/report/vendor/`, with its MIT licence and provenance. It is checked against its SHA-384 hash at load and embedded inline under a hash-based CSP. The report makes no network request and renders offline (tested) |
| #22 | 15 | **Contract schema v2:** `must_not_reach` can name an `application` or `service_principal`, with `credentials/update` and `owners/update`. The seeded contract guards `id-verifier`, `sp-fns-scout` and `listKeys` on invoices. A new detection rule covers owner changes. Mutation survivors now say what the model saw. FINDINGS: "Mutation testing found a gap in our own contract". **Score 6/8, not 8/8** (see below) |
| #23 | 4 | **PIM eligibility collector.** It records one of three states: collected, not-applicable *with evidence* (the listing's status and error code, plus the subscribed SKUs), or not-collected. Eligibility of anything the attacker controls keeps every finding open. The scout gets Graph `LicenseAssignment.Read.All` in the lab. Existing snapshot digests are unchanged |
| #24 | README diagram | Two top-down Mermaid diagrams. The main flow has subgraphs Inventory, Antivenom, Prove, Harden / Mutate and Report. A second diagram shows the trust boundaries, with the verifier marked |
| #25 | runbook, follow-up questions | `docs/runbooks/m2-live-run.md` is updated for v2 and PIM and is ready to run. Step 6 explains the two survivors. DECISIONS, FINDINGS and the README record the answers below |
| #26 | STATUS | This file |

Tests: 804 before the review, 888 after, plus 1 Linux-only test of the Action's
bash script.

### Your two follow-up questions

#### 1. Which two mutants survive, and can a contract change kill them?

There are eight mutants:

- Owner on the resource group;
- the key-operator role on each of the two storage accounts;
- three privileged Graph permissions;
- ownership of each of the two applications the agent does not already own.

`remove-deny-assignment` is `n/a`, not a survivor. The lab has no deny assignment
to remove: Azure creates deny assignments only for managed applications and
deployment stacks, and the lab uses neither. It is not one of the eight.

The survivors are **`app-owner:id-verifier`** and **`app-owner:sp-fns-scout`**.
Each makes the agent an owner of that application.

- **Why they survive.** `--harden` removes the agent's
  `Application.ReadWrite.OwnedBy`, and the agent never had
  `Application.ReadWrite.All`. An app-only caller needs one of these two
  permissions to add a credential to an application it owns, or to change that
  application's owners. With the ownership alone, the agent cannot perform any
  operation the contract forbids.
- **No contract change kills them.** `must_not_reach` lists operations, and none
  of them becomes reachable. Killing these mutants would take a new kind of
  check that fails on the ownership itself (option (b) below), not another
  contract line.
- **The attack is still covered.** The other half of the attack is the Graph
  grant that would make the ownership usable. The three `graph-app-permission`
  mutants already catch that.

**Decision:** I marked them as accepted, explained survivors (option (a)). The
runbook runs `fns mutate --max-survivors 2` and has you check the two survivor
names by hand, because `--max-survivors` allows a count, not specific names. The
expected score stays **6/8**.

Two other ways to raise the score, both left undone. Each would change the kill
rule or what "reach" means:

- **(b)** a standing-ownership check that fails on any owner of a protected
  object;
- **(c)** a compound "ownership plus OwnedBy" mutant.

#### 2. Is `LicenseAssignment.Read.All` needed, given `Directory.Read.All`?

Not today: `Directory.Read.All` already covers `/subscribedSkus`, so the extra
grant adds no access. I kept it because it is needed to drop `Directory.Read.All`
later.

- **What the later run looks like.** The planned run with
  `scout_directory_read_all = false` leaves the scout with
  `Application.Read.All`, `RoleManagement.Read.Directory` and
  `LicenseAssignment.Read.All`.
- **Why it is needed there.** It is the only one of the three that covers
  `/subscribedSkus`. Without the licence evidence, `pim-eligibility` can never be
  `not-applicable`, so in a tenant without PIM no `must_not_reach` item could
  pass.
- **Why this permission.** It is the narrowest one that covers the call.
  `Organization.Read.All` also works, but it is broader.
- **Why it is not tied to the toggle.** Granting it only when `Directory.Read.All`
  is off would make the toggle run change two grants instead of one.

The reasoning is in `docs/DECISIONS.md`.

### Still open for your review

- **PIM eligibility is handled coarsely.** Any eligibility of a controlled
  principal leaves *every* finding open. Narrowing it by scope or by operation
  can come later.

### Not verified yet

These depend on the live run:

- **Eligibility in a tenant without P2.** *Answered in the M2 run: see the first
  two rows of `docs/FINDINGS.md`.* What Graph and ARM actually return was
  unknown. The tests use an illustrative `AadPremiumLicenseRequired`; the
  collector records whatever code comes back and does not depend on that one.
- **Audit activity names.** The names in the two credential and owner detection
  rules come from Microsoft's documentation. They have not yet appeared in lab
  logs.
- **`LicenseAssignment.Read.All` alone for `/subscribedSkus`.** Whether it is
  enough shows up only in the `scout_directory_read_all = false` run.
- **Ownership without `OwnedBy`.** The survivors rest on the documented rule that
  an app-only owner without `OwnedBy` or `.All` cannot change the application.
  This is modeled, not observed. Observing it needs a write, so it belongs to the
  M4 strikes, or to the R1 probe if ARM-style authorize-before-validate also holds
  for Graph.

### Next (done)

The M2 run is done, `fixtures/lab-run-2` is its regression test, the PIM
responses are in `docs/FINDINGS.md`, and `m2` is tagged.
