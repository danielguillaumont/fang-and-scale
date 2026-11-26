# Status after the 2026-11-26 morning review

## Milestone results

| Milestone | Live run | Result | Regression test |
| --- | --- | --- | --- |
| M1 Scout | 2026-11-26 | scout as the admin, then as `sp-fns-scout` | `fixtures/lab-run-1` |
| M2 Contain | 2026-11-26 | critical reachable 11, inconclusive 2, exit 1; mutation 6/8 with the two accepted app-owner survivors | `tests/fixtures/test_lab_run_2.py` |
| M3 Prove | 2026-11-26, probes as `sp-billing-agent` | passed 1 (invoices `blob/read`, observed and verified), critical reachable 11, still-do failed 0, inconclusive 1, exit 1. The Key Vault and payroll reads were denied when probed and still fail: escalation paths remain | `tests/fixtures/test_lab_run_3.py` |


Every item from the morning review of `docs/OVERNIGHT.md` is done. Each one got
its own branch and PR. CI passed on ubuntu and windows on the first run every
time, and all of them are merged to `main`. No Azure call, `az` command or
Terraform apply was made. Everything was tested with fixtures and mocks.

## What changed

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

## Your two follow-up questions

### 1. Which two mutants survive, and can a contract change kill them?

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

### 2. Is `LicenseAssignment.Read.All` needed, given `Directory.Read.All`?

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

## Still open for your review

- **PIM eligibility is handled coarsely.** Any eligibility of a controlled
  principal leaves *every* finding open. Narrowing it by scope or by operation
  can come later.

## Not verified yet

These depend on the live run:

- **Eligibility in a tenant without P2.** What Graph and ARM actually return is
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

## Next

Run `docs/runbooks/m2-live-run.md`, then:

- commit `fixtures/lab-run-2` as the C4 regression test;
- record the PIM responses in `docs/FINDINGS.md`;
- tag `m2`.

I stopped here, as asked.
