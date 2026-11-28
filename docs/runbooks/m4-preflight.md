# M4 preflight: before session A

One page to go through before [`m4-live-run.md`](m4-live-run.md) session A, and
again, briefly, before B, C and D. Nothing here calls Azure. Prices are the M4
plan's estimates (`docs/milestones/M4-plan.md`, "Trials, cost and expiry"):
check them in the pricing calculator on the day.

## 1. Money

- [ ] **Credit left.** Portal, **Education** hub (search "Education"): write down
  what is left before each session, and again after it. Azure for Students has a
  spending limit, so running out stops resources rather than billing a card.
- [ ] **`budget_alert_email` is empty** in `lab/terraform.tfvars`. Cost
  Management does not support Azure for Students, and a plan with the budget
  fails on it (`lab/README.md`, "Cost alert").
- [ ] **Expected cost per session:**

  | Session | What bills | Expected |
  | --- | --- | --- |
  | A | the lab: 1 Key Vault, 2 LRS storage accounts | cents per day while the lab is up |
  | B | Log Analytics and Sentinel start: ingestion is waived by the 31-day Sentinel trial (up to 10 GB a day); the workspace is capped at `monitoring_daily_quota_gb` = 1 GB a day | about $0 inside the trial |
  | C | strike calls, queries (free), ingestion inside the trial | well under $1 |
  | D | probes, D-steps, ingestion inside the trial | well under $1 |
  | Teardown | nothing once `lab-down` is done | $0 |

  **All of M4: under $5**, if C and D fall inside the trial and Teardown runs.
  The real risk is a workspace left up after the trial: Sentinel then bills per
  GB for as long as it exists.

## 2. Time and clocks

| Session | Time | Clock it starts or needs |
| --- | --- | --- |
| A | 1.5 h | **scope: 7 days** from A2 (`scope_valid_days`). Every session must start inside it, or renew it first (section 4) |
| B | 1 h, plus 15 min or more for blob logs | **Sentinel trial: 31 days** from B1's apply (Terraform onboards the workspace). C and D must finish inside it |
| C | 2 h, mostly the C6 alert polling | **strike window: 4 hours** from C1 (`strike_valid_hours`): C3 and C4 must run inside it. **Plan: 1 hour** from C3 to C4 |
| D | 1.5 h | the strike window has usually closed: D5 renews it. Plan: 1 hour from D6's plan to its run |
| Teardown | 15 min | before the trial's day 31 |

- **Certificates:** each is valid for 23 hours and is deleted in the same
  session. A new one takes about 3 minutes before it signs in.
- **Suggested order:** A and B on one day; C and D on one day, within a week of
  A2 and well inside the trial; Teardown as soon as the fixtures are committed.
- [ ] Put the trial's day 31 (from B1) and the scope's day 7 (from A2) in your
  calendar.

## 3. This laptop

- [ ] **Sleep off** (plugged in) before the session starts: **Settings, System,
  Power, Screen and sleep**, "Never". Write down the old values. Sleep in the
  middle of `fns strike run`, a Terraform apply or the C6 polling loop is
  exactly the "session dies" case.
- [ ] **Sleep back on** after the session's last verify block printed what it
  should (certificates deleted, profiles gone).
- [ ] **Claude Code in manual mode** while any window is signed in to Azure,
  as you or as a lab identity. Your `az login` is Global Administrator, and its
  token cache (`%USERPROFILE%\.azure`) and the two lab profiles under `%TEMP%` are
  readable by any process you run. Switch it out of auto mode before the first
  `az login` (Shift+Tab cycles the modes), and approve nothing that runs `az`,
  `terraform`, `fns scout`, `fns strike`, `fns prove` or reads those
  directories. Paste outputs into it; don't let it run them. Back to auto only
  after the session's `az logout`.
- [ ] One PowerShell window per session, opened at the repository root.

## 4. Commands that prompt: paste each one alone

Terraform reads the next pasted line as the answer to its `yes` prompt
(FINDINGS, 2026-11-27). Each of these is in a block of its own in the runbook.
Paste it, read the plan, type the answer yourself.

| Step | Command | Plan to expect |
| --- | --- | --- |
| A2, B1, C1, D3 | `uv run poe lab-up` | the counts in that step |
| D5 | `terraform -chdir=lab apply "-replace=time_offset.strike_expiry[0]"` | 2 to add, 0 to change, 2 to destroy |
| Any session more than 7 days after A2 | `terraform -chdir=lab apply "-replace=time_offset.scope_expiry"` (renews the scope) | 2 to add, 0 to change, 2 to destroy |
| Teardown; emergency step 4 | `uv run poe lab-down` | everything A2, B1 and C1 added, less the two grants D3 removed |

`az login --tenant <TENANT_ID>` opens a sign-in window: run it alone too, and
wait for it to return before the next line.

## 5. What to paste back after each session

The runbook's "Report back" lists the outputs per session. Before pasting:

- **Replace every GUID** (tenant, subscription, object and app IDs) with the lab
  name or `<id>`. `scope check`, the scout summary and `fns strike` print them.
  Storage and vault names with the lab suffix are fine.
- **Never paste:** `.fns\m4\logs\*.json` (real IDs), `scope.lab.yaml`,
  `plan.json`, any `_idmap.json`, the output of `az ad app credential reset`
  (it names the PEM file), or a PEM file's content.
- Always include each `$LASTEXITCODE`, and anything that differed from an
  "Expected" line.

## 6. Stop, and emergency cleanup

**Stop** (clean up what the step made, then report back):

- a Terraform plan with other counts than the runbook's: answer `no`;
- `scope check` shows another tenant or subscription, or the scope has expired;
- `fns strike plan` lists another target, method or body key than the review
  table;
- `harden` proposes anything other than the two grants in D2;
- a D-step shows `unexpected-success`, or D7 exits 1 or 3;
- the credit dropped by more than $5 in one session.

**Emergency cleanup now** (runbook, "Emergency cleanup"):

- the window, the laptop or the network died during C2 to C5 or D6 to D8;
- `fns strike run` or `fns strike cleanup` exits 5, or any line reads
  `verify FAIL` or `needs-emergency-cleanup`;
- a credential list that must print nothing prints something, or a PEM file is
  still there after its delete step;
- you are unsure what state the lab is in.

If the trial's day 31 is near and D is not done: Teardown first, rebuild later.
