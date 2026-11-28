# Status

## v0.1.0 is released (2026-11-27)

Daniel tagged `v0.1.0` on #86's merge commit (`0ddfa34`) and published the
release. The GitHub release shows 2026-11-28 01:26 UTC. Its build provenance
attestations verify. `CHANGELOG.md` has a new, empty "Unreleased" section, and
#87 (DECISIONS only) is the first entry in it.

### Front-page session (2026-11-27)

Same hard rules: no Azure, no tags, PRs with required CI, STATUS current.

| # | Item | State | PR |
| --- | --- | --- | --- |
| 1 | Post-release housekeeping: "Unreleased" with #87, STATUS | done | #88 |
| 2 | CI: install the built wheel in a clean venv and run `fns demo contain --bundled` | done | #89 |
| 3 | README rework, with generated demo output and a sample FIXTURE report | to do | |
| 4 | `docs/social-preview.png` (1280x640) | to do | |

## Owner-decision session (2026-11-27)

Working through Daniel's decisions of 2026-11-27, one focused PR per item. Same
hard rules as before: no Azure, Graph or Log Analytics call, no `az`, Terraform
only as `poe lab-check`, fixtures and mocked transports only. CI (three checks)
is required on `main`. Nothing was tagged in this session; Daniel tagged and
published v0.1.0 afterwards (above).

### Queue

Third batch (Daniel's decisions on the exit-3 gap and the tag commit; marked in
DECISIONS in #84):

| # | Item | State | PR |
| --- | --- | --- | --- |
| 9 | D-6 and D-7: `listKeys` after harden on both storage accounts, and `listKeys` in option B's table | done | #84 |
| 10 | The lab budget: `max_inconclusive: 3`, the three items named with reasons, any other inconclusive fails; runbook D7; the logged `blob/write` future proposal | done | #85 |
| 11 | Fold option B, #83, #84 and #85 into the 0.1.0 changelog; the tag commands on `main` | done | #86 |

Second batch:

| # | Item | State | PR |
| --- | --- | --- | --- |
| 7 | Build option B, with the PIM precondition and the runbook's session-D results | done | #82 |
| 8 | The attestation token reachable from its step only | done | #83 |

First batch:

| # | Item | State | PR |
| --- | --- | --- | --- |
| 1 | Mark the decisions in `docs/DECISIONS.md` | done | #76 |
| 2 | Agent ID findings `not-assessed` | done | #77 |
| 3 | S4, with the runbook update | done | #78 |
| 4 | Threat model open gaps (size caps, provenance attestation) | done | #79 |
| 5 | v0.1.0 release prep (date, `release-check`, the tag commands for Daniel) | done | #80 |
| 6 | M4 exit gate, option B: plan only, then stop | done (plan only) | #81 |

### Decisions of 2026-11-27 (marked in `docs/DECISIONS.md`)

- **Exit-3 gap.** (1) Approved and **built (#84)**: D-6 (payroll) and D-7
  (invoices) try `listKeys` after harden and must be denied. A LIVE 403 on the
  account's exact ARM ID counts under option B. If one ever succeeds, both of
  that account's keys are regenerated at once (as SD1), the scout verifies it,
  the item fails and the run exits 1. (2) Not now: logged `blob/write` evidence
  stays out of verdicts. It is written up as a future proposal only
  (`docs/proposals/logged-blob-write-evidence.md`, #85). (3) Approved and **built
  (#85)**: the lab contract's `max_inconclusive` is 3 and names invoices
  `blob/write`, the tenant-wide `applications/credentials/update` and
  `roleAssignments/write`, each with its reason. Any other inconclusive item is
  over budget (exit 3) even within the count.
- **Session D now expects exit 0** only if those three are the only inconclusive
  items and no surface is open (runbook D7; `tests/prove/test_session_d_budget.py`
  replays the hardened lab-run-2 with every D-step denied).
- **Tag `main`, not #81.** Option B, #83, #84 and #85 are folded into 0.1.0
  (#86), and `uv run poe release-check` prints `release check: ok`.
- Every other "Pending review" row: approved (Agent ID as built, the two open
  gaps as built, option B as built, the attestation job).
- Earlier the same day: S4 approved with conditions and built (#78); option B
  approved and built (#82), with the PIM precondition; the attestation token
  scope approved and narrowed to one job (#83); M6 Agent ID licensing and the
  LLM bake-off deferred.

### Needs Daniel

- ~~Two rows pending review in DECISIONS~~: how D-6 and D-7 are built (#84) and
  how the named inconclusive budget is built (#85). **Both approved 2026-11-27.**
- **M4 sessions A to D** have still not run live: `docs/runbooks/m4-live-run.md`.
  Session D now runs D-1 to D-7.


## Summary of the build session: the queue is done (2026-11-27)

All ten queue items are merged, except S4, which waits for your decision. No
Azure, Graph or Log Analytics call was made, no `az` command ran, and Terraform
ran only as `poe lab-check` (fmt and validate). Every PR passed CI before it
merged. Nothing was tagged or published.

**Tests:** 1402 passed at the start of the overnight session, 1701 after the
night's last PR (#69), and **1876** now. Each count is on Windows, with 1 more
test skipped (the Action's bash script, which runs only on Linux).

### What changed, by PR

| Item | PRs | In short |
| --- | --- | --- |
| 1. M4 log path check | #60 | Step 1 passed; D1 stands |
| 2. Detection rules | #61, #62 | Sample rows run by a KQL subset evaluator; `lab/monitoring.tf`, off by default |
| 3. Lab group (D3) | #63 | `grp-fns-billing`, the agent its only member, no roles |
| 4. Strike engine | #64 to #67 | Plans with hash approval and 1-hour expiry, journaled writes and undos, read-back by a second identity, journal-driven cleanup; `fns strike`; the lab's `strike:` block; D-1 to D-5 as verdict evidence under the "never looser" guardrail. **S4 is not built** (Needs Daniel) |
| 5. M4 live runbook | #68 | Sessions A to D, step by step |
| 6. Report and UX | #69 | Strike runs, detection results and the evidence ladder on the report page |
| 7. v0.1 release prep | #70 | Version 0.1.0, CHANGELOG, a draft-only release workflow on `v*` tags with SBOM and checksums, QUICKSTART, `fns demo --bundled`. **Not tagged** |
| 8. Architecture and threat model | #71 | Six trust boundaries with diagrams; seven hostile inputs, each with what does **not** hold; open gaps |
| 9. M6 groundwork | #72, #73 | `fns mcp serve`, a read-only MCP server (standard library only); design notes for Agent ID and the LLM bake-off |
| 10. Hardening and quality | #74, #75 | The terminal shows control characters from tenant strings as escapes; the coverage gaps in the write gate, the strike engine and the verifier are closed with tests; property tests; test journals skip fsync (the top-level tests ran about 21% faster, back to back) |

Findings along the way, each with a test or a DECISIONS row:
- **Terminal escape injection.** Rich passed ESC from display names through to
  the terminal. This is fixed in #74.
- **Agent ID inheritance.** Today's collector would type an agent identity as a
  plain service principal, so the permissions it inherits from its blueprint
  would be invisible to the model. #73 proposes how to handle it; nothing is
  built.
- **Microsoft's Agent ID docs disagree with themselves** on how a blueprint
  principal is created. This is V-A1 in `docs/milestones/M6-agent-id.md`.
- **Encoding depth.** The write gate's denylist decodes at most 16 rounds of
  percent-encoding. From 17 rounds, the strict URL rule refuses the request
  instead. That defence in depth is now pinned by a test.

### Decisions pending review (all approved 2026-11-27)

All are in `docs/DECISIONS.md`, marked "Pending review". The ones from this
session:

- **Strike engine** (#64 to #69): transport errors count as sent, so the undo
  runs; a lost `addPassword` answer is undone by name; after-harden successes
  are undone at once; the `fns strike` exit codes; two CLI config dirs; ARM
  targets need the lab tags; the `strike:` block is rendered only when enabled;
  how a strike observation affects a finding; the runbook's identity and cleanup
  choices; detection results are display-only.
- **Release** (#70): a draft from a `v*` tag, never PyPI; install from a Git tag
  with `--python 3.12`; `fns demo --bundled`.
- **Threat model** (#71): the "Open gaps" table, where each fix waits for a
  decision.
- **MCP server** (#72): the standard library instead of the `mcp` SDK, and what
  the server will open.
- **M6** (#73): Agent ID findings stay `not-assessed` until inheritance is
  modeled, and the bake-off's output is limited to the lever set.
- **Tests** (#75): test journals skip fsync; the product keeps FULL.

### Needs Daniel (as of the build session; see the owner-decision session above)

Each item is described in full below, under "Needs Daniel":
1. **S4 gate rules:** S4 needs a token form and a write as a non-test identity.
2. **D6 and the M4 exit gate:** after harden, session D's prove is expected to
   exit 3. Choose option a, b or c.
3. **Releasing v0.1.0:** four steps, when you want it.
4. **M6 inputs:** Agent ID licensing and cost, and the models for the bake-off
   and who pays for it.
5. **Repository settings I may not change:** require CI to pass on `main` (one
   command in `docs/PUBLIC-READINESS.md`), and require reviews once there is a
   second maintainer. Both are THREAT-MODEL open gaps.

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
| #65 | 4 (part 2) | **`fns strike plan | run | cleanup`.** Live mode signs in two identities from two Azure CLI config dirs (agent writes, scout reads), checked before any call. `--fixture fixtures/strike-demo` replays a strict recording, generated from the fake tenant and labelled FIXTURE. ARM targets must carry the lab tags. Proposal for S4's gate rules recorded (pending review) | 1621 |
| #66 | 4 (part 3) | **`lab/scope.tf` renders the `strike:` block**, only with `enable_strikes = true` (off by default; 1 more resource when on). The seven write forms the built strikes use, the five lab targets by Terraform reference, a 4-hour strike expiry. `lab-check` passes; tests render the template both ways and load it through the engine | 1625 |
| #67 | 4 (part 4) | **D-1 to D-5 as verdict evidence (D6), with the guardrail.** `fns prove --after-strike <strike run dir>` (and `fns demo prove`) records each after-harden attempt as a frozen, journaled strike observation. The verifier adds a denial as context only. A success against a `must_not_reach` item fails it, and code refuses any verdict that would loosen. A new test re-runs every prove golden with every item struck, all denied and all succeeded: no finding moves toward pass, and denials change no decision. A strike run from another plan, tenant or mode is refused before anything is written. A tampered strike artifact fails `check`. The real `fixtures/strike-demo` after-harden run maps onto exactly the five application and directory items | 1649 |
| #68 | 5 | **M4 live runbook** (`docs/runbooks/m4-live-run.md`), sessions A to D. It covers: rebuild; monitoring on (workspace, Sentinel, diagnostic settings, the 11 rules); legitimate use and `fns record`; strikes on; S1 to S3 with two CLI profiles; one KQL query per strike plus an alert query (D5); harden and apply; D-1 to D-5; `prove --live --after-strike`; teardown; and an emergency cleanup for every write a strike can make. Exact PowerShell, prompting commands alone, no real values. `tests/test_runbook_m4_live.py` checks every `fns` option, Terraform output, plan count, certificate lifetime and query column against the code. README and M4 plan point to it | 1675 |
| #69 | 6 | **The report shows strikes, detections and the evidence ladder.**<br>`fns report --strike <dir>` (repeatable) shows each strike run: writes, outcomes, undos, what each observes, the scout's verification and the exit code.<br>`--detections <file>` shows the D5 results per strike: fired with latency, `detection-gap`, or no source rows. The new format (`schemas/detection-results.schema.json`) is operator-reported and never evidence.<br>Every finding gets a ladder column (one cell per rung, context marked). With `--prove`, its evidence table shows the bundle's evidence and roles.<br>The report refuses a strike run from another tenant or mode, or one that does not match its plan, and refuses detections for a run not on the page.<br>`strike-run.json` is read through one model (`StrikeRunRecord`) by the report and by `prove --after-strike`.<br>Cytoscape was already vendored and pinned by its SRI hash, and the page is still self-contained.<br>Golden: `tests/golden/report-strike-demo.html`, built through the real commands from demo-scout and strike-demo | 1701 |
| #70 | 7 | **v0.1.0 release prep (no tag, no publish).**<br>Version `0.1.0` in `pyproject.toml` and `uv.lock`. `CHANGELOG.md` covers everything to date, including what did not run live; it says "not tagged yet".<br>`.github/workflows/release.yml` runs only on a `v*` tag. It checks that the tag, version, changelog date and lock agree (`scripts/release_check.py`), runs `poe check`, builds, writes a CycloneDX SBOM (`uv export`, no new dependency) and SHA-256 sums, and creates a **draft** release. Nothing goes to PyPI.<br>`poe release-check` and `poe sbom` run the same steps locally.<br>`docs/QUICKSTART.md` covers `pipx` or `uv tool` install from the Git tag with `--python 3.12`, or a checkout.<br>`fns demo --bundled` replays the packaged hand-written set without a checkout. Without the flag nothing changes.<br>A built wheel installed into a clean venv ran `fns demo` outside the repo.<br>The README has an Install section and an honest status line | 1722 |
| #71 | 8 | **`docs/ARCHITECTURE.md` and `docs/THREAT-MODEL.md`.**<br>ARCHITECTURE has the roles, which ones hold credentials or write, and five trust boundaries as Mermaid diagrams: the gate, the separate verifier, the approved-only executor, labelled fixtures, and untrusted tenant data. Each boundary names what enforces it.<br>THREAT-MODEL covers a hostile tool, fixture, scope file, contract, tenant data, run directory and pull request. Each section says what stops the attack and what does **not**.<br>Open gaps found while writing it: terminal output keeps ESC from tenant strings (fix planned in item 10), JSON inputs have no size cap, release files are not attested, and CI and reviews are not required on `main`.<br>`tests/test_architecture_docs.py` fails if a named file, module or import contract disappears, or if the exit-code table drifts | 1731 |
| #72 | 9 | **`fns mcp serve`: a read-only MCP server on stdio.**<br>It is standard-library JSON-RPC 2.0, with no new dependency. Five tools, each annotated read-only and closed-world:<br>- `list_fixtures` and `read_fixture_file`: from a fixed file list that never includes `_idmap.json` or `exchanges.json`;<br>- `contain_fixture`: a FIXTURE replay in a temporary directory;<br>- `list_reports` and `read_report`: from `--reports` only, FIXTURE unless `--include-live`, and refused if the content does not hash to the file name.<br>Names are pattern-checked and must resolve inside their root (no `..`, no symlink out). Files over 8 MiB and lines over 1 MiB are refused.<br>A new import contract keeps it away from the live transport, credentials, scout, the executor, the prover, the verifier and the proposer.<br>Tests: a canary ID map, a socket that raises if opened, and a real stdio subprocess.<br>The README has a client config example; ARCHITECTURE gains boundary 6 | 1791 |
| #73 | 9 | **M6 design notes (nothing built):**<br>- `docs/milestones/M6-agent-id.md` uses Microsoft Learn, read 2026-11-27, and lists six lab checks (V-A1 to V-A6) before code depends on it. It found a gap: today an agent identity is collected as a plain service principal, so the permissions it inherits from its blueprint are invisible to the model. It proposes `not-assessed` until inheritance is modeled.<br>- `docs/milestones/M6-bakeoff.md`: the LLM is a proposer only, its output is limited to the `fns.harden.tfmap` levers, and both contestants are scored by the existing evaluator and `fns mutate`. It includes hostile-string cases, runs locally only, and picks no models yet.<br>`tests/test_m6_notes.py` keeps both marked as design only and true about the code | 1798 |
| #74 | 10 | **Control characters from tenant strings are shown as escapes in the terminal.** Every console is now a `SafeConsole`. It makes C0 and C1 controls, DEL and the bidi controls visible (`\x1b[2J`, `\u202e`) before layout, so tables size for the escaped text. A segment-level pass after layout backstops `Text` objects. Rich's own colours are unaffected.<br>Tests: each kind of character, markup on and off, tables, `Text`, the FIXTURE console, no terminal, a Hypothesis property over any string, and a fixture whose display name holds `ESC[2J`, through `fns demo contain`.<br>This closes the THREAT-MODEL "Open gaps" row found in #71 | 1806 |
| #75 | 10 | **Coverage gaps closed, property tests, faster test journals.** I measured branch coverage with `uv run --with coverage`, with no new dependency. Before the new tests:<br>- the write gate was at 96%;<br>- the strike engine was at 96%;<br>- the verifier's `inputs.py` was at 74% in-process, and the D6 guardrail was reached only through subprocesses.<br>New tests pin every uncovered refusal with its exact reason:<br>- deep or non-string bodies, over-long tags, non-canonical ARM paths, a child resource of a target, an app that has not passed the live check;<br>- percent-encoding: up to 16 rounds is hard-denied, and from 17 the strict URL rule refuses it;<br>- untagged ARM targets get no plan; a lab that cannot be re-read is never written; cleanup as another identity is refused;<br>- an unresolvable undo is recorded, exits 5, and a later cleanup finishes it; a failed or nonsensical read-back is never "restored";<br>- unfinished probes; forged artifacts (another probe, rung or mode); strike artifacts in-process.<br>Property tests:<br>- the guardrail over real findings and any strike observations: rank never rises, evidence only grows, denials change nothing;<br>- any MCP fixture name is refused or is a listed set.<br>Test journals skip fsync; the product keeps FULL, and a test pins that. Back to back, the top-level tests ran about 21% faster.<br>No refusal branch needed a code change | 1876 |

Tests at the start of the session: 1402 passed, 1 skipped (the Action's bash script, Linux only). Counts below are passed tests on Windows.

### Queue position

1. ~~Log path check results~~ (#60)
2. ~~Detection rules~~: sample-row tests (#61), `lab/monitoring.tf` (#62)
3. ~~Lab group (D3)~~ (#63)
4. ~~Strike engine~~: core (#64), command and replay (#65), `lab/scope.tf` strike block (#66), D-1 to D-5 as verdict evidence (#67). S4 waits for a decision (Needs Daniel)
5. ~~M4 live runbook~~ (#68)
6. ~~Report and UX~~ (#69)
7. ~~v0.1 release prep~~ (#70; tagging is yours, see Needs Daniel)
8. ~~ARCHITECTURE and THREAT-MODEL~~ (#71)
9. ~~M6 groundwork~~: read-only MCP server (#72), Agent ID and bake-off notes (#73)
10. ~~Hardening and quality~~: terminal control characters (#74), coverage gaps, property tests and faster test journals (#75)

The queue is done. See the summary at the top.

### Needs Daniel (as of the build session; see the owner-decision session above)

- **S4 gate rules** (`docs/DECISIONS.md`, "Proposal, pending review: S4"). S4 signs in as
  `app-escalation-target` with S3's password and assigns the marker role. That needs a
  `token:` form for `login.microsoftonline.com` and a gate rule allowing writes as a
  non-test identity. The strike plan leaves both to "its own decision", and CLAUDE.md
  asks for an approved plan before a scope change, so S4 is not built. Everything else in
  item 4 goes ahead without it.

- **D6 and the M4 exit gate.** With the guardrail as approved ("no finding moves
  toward pass because of strike evidence"), D-1 to D-5 denials are context only
  (#67). After harden, the four application items and `directory:tenant
  applications/credentials/update` therefore stay `inconclusive`, plus
  `roleAssignments/write` (SD3). That is six over a `max_inconclusive` of 2, so the
  live prove in session D is expected to exit **3**, and the runbook says so.
  Options:
  - **a.** Keep it: raise `max_inconclusive` in the lab contract, with a reason
    per item.
  - **b.** Allow an observed strike denial to count like an observed probe
    denial, so `pass` needs both the denial and every path refuted with no open
    surface. This moves those items toward pass, so it would need your explicit
    change to the guardrail and its own plan.
  - **c.** Something else.

  Option b was chosen on 2026-11-27. Its plan is `docs/milestones/M4-exit-gate-plan.md`
  (#81); nothing is built for it.

- **Releasing v0.1.0** (when you want it; nothing is tagged or published).
  Steps 1 and 2 are done (#80); the exact commands are in the owner-decision
  session's "Needs Daniel" above:
  1. Done: `CHANGELOG.md` is dated 2026-11-27.
  2. Done: `uv run poe release-check` prints `ok`.
  3. `git tag v0.1.0` on `main`, then `git push origin v0.1.0`.
  4. The release workflow builds, checks and creates a **draft** release with the
     wheel, sdist, `sbom.cdx.json` and `SHA256SUMS`. Review it on GitHub, then
     publish it.

- **M6 inputs** (not needed until M6 starts):
  - **Agent ID in the lab** (V-A6 in `docs/milestones/M6-agent-id.md`): whether it
    needs a preview, P1/P2 or other licence in the lab tenant, and what it costs.
  - **The bake-off:** which models and providers to compare, and who pays for the
    runs (`docs/milestones/M6-bakeoff.md`).

### Pending review (all approved 2026-11-27)

Approved on 2026-11-27 (marked in `docs/DECISIONS.md`): the KQL evaluator, the
two rule choices, the 1 GB cap, both ID kinds monitored, the plan expiry and
pre-state re-read, journal-driven cleanup, the `strike_events` table, and D-1 to
D-5 as verdict evidence with the "never looser" guardrail.

Still pending (strike engine, #64; not in the approved list):

- a transport error counts as "sent", so the undo runs (S1 regenerates both keys);
- a lost `addPassword` answer is undone by the run's credential name;
- an after-harden attempt that succeeds is undone at once;
- `fns strike` exit codes 0 / 1 / 4 / 5, with 5 (verification failed) first; refusals
  before any write (hash, identity, scope, changed lab) are 4 (#65);
- two Azure CLI config dirs for the agent and the scout (#65);
- ARM strike targets must carry the lab tags (#65).
- the `strike:` block is rendered only with `enable_strikes`, and lists only the built strikes' forms (#66);
- what a strike observation does to a finding: a denial is context, a success fails a
  `must_not_reach` item, and non-counting outcomes are dropped (#67).
- the M4 live runbook's identity and cleanup choices (two profiles, a certificate per
  step, logs kept in `.fns`, the narrow S2 and owner undos) (#68).
- detection results are an operator-reported file, shown in the report and never
  evidence (#69).
- the release is a draft from a `v*` tag, never PyPI; the install path is a Git tag
  with `--python 3.12` (#70).
- the MCP server: standard library instead of the `mcp` SDK, and what it will open
  (fixed fixture files, FIXTURE reports unless `--include-live`) (#72).
- Agent ID findings `not-assessed` until inheritance is modeled, and the bake-off's
  levers-only output (#73).
- test journals skip fsync; the product keeps FULL (#75).
- the threat model's "Open gaps" table: each fix waits for a decision (#71). The
  terminal control-character gap is fixed (#74).

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
