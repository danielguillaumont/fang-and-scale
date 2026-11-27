# M4 exit gate: option B (plan only)

Status: **proposed, not approved.** No code until Daniel approves this plan.
Decision row: `docs/DECISIONS.md`, 2026-11-27, "M4 exit gate: option B, plan only".

## The problem

The D6 guardrail (#67) says strike evidence may only add context or make a
verdict stricter. After harden, D-2 to D-5 are denied, but those denials are
context only. So the four application items stay `inconclusive`, because no
probe can observe them. That makes six inconclusive findings against the lab
contract's `max_inconclusive: 2`:

- `application:id-verifier credentials/update`
- `application:id-verifier owners/update`
- `application:sp-fns-scout credentials/update`
- `application:sp-fns-scout owners/update`
- `directory:tenant applications/credentials/update`
- `directory:tenant roleAssignments/write`

So session D's prove is expected to exit 3 (`docs/runbooks/m4-live-run.md`, D7).

Option B lets a strike denial count where a probe denial would, under stricter
conditions than a probe gets. Nothing else in the verdict rules changes.

## The rule

A strike observation is a **counting denial** for a `must_not_reach` finding only
if every condition below holds:

| # | Condition | Why |
| --- | --- | --- |
| 1 | The strike run, the frozen assertions and the observation are all `LIVE` | FIXTURE never counts. A recording can show the tool works, not that a tenant is safe |
| 2 | The strike is D-2, D-3, D-4 or D-5 (after harden, planned `expect: denied`) | D-1 observes a first hop, not a contract item. Before-harden strikes and S4 never count (#78) |
| 3 | The outcome is `denied` and the HTTP status is exactly **403** | The probes' own rule (V5, `fns.probes.data_read`): a 401 can be an expired or wrong token, not a decision on the request, so it counts as `unknown`. So does anything else: 400, 404, a gate denial, a timeout, not run |
| 4 | The write's request is the contract item's **exact operation on the exact target** (the table below) | A denial of one request must not stand for a different operation, or for every object of a kind |
| 5 | The item is not `directory:tenant roleAssignments/write` | SD3: no direct attempt is possible or planned, so it stays `inconclusive` |

A counting denial then goes into the probe rules (`fns.verify.verdict.judge`) in
the same slot as an observed `data-read` denial. That keeps every existing
requirement for `pass`:

- the denial;
- **and** every modeled path refuted;
- **and** no open coverage surface.

Under these rules:

- **A denial without refuted paths stays as judged.** An unrefuted path still
  fails the item, as it does today. When the model has no path but surfaces are
  open, the item stays `inconclusive`, with the reason "denied (strike), but not
  collected: ...".
- **Every attempt counts.** Several attempts on one item combine as probes do: if
  any one was allowed, the item counts as allowed. A strike success still fails
  the item, as it does today.

### The exact-operation table

The verifier holds this table itself, in `fns.verify`. It imports nothing from
`fns.strike`.

| Strike | Request (`PlannedRequest.operation`) | Counts for | Does not count for |
| --- | --- | --- | --- |
| D-2 | `graph:POST /applications/{id}/addPassword` on id-verifier's app | `application:id-verifier credentials/update` | `directory:tenant applications/credentials/update`: one app is not every app, so that item stays context |
| D-3 | the same, on sp-fns-scout's app | `application:sp-fns-scout credentials/update` | |
| D-4 | `graph:POST /applications/{id}/owners/$ref` on id-verifier's app | `application:id-verifier owners/update` | |
| D-5 | the same, on sp-fns-scout's app | `application:sp-fns-scout owners/update` | |

To check condition 4 without trusting the plan's `observes` text, the
`StrikeObservation` model gains two omit-empty fields, both copied from the
planned write:

- `request_operation`;
- `request_object_id`, the object ID in the request URL.

The frozen assertion gains `target_object_id`, an omit-empty field taken from
the snapshot at freeze time. The verifier counts the denial only if:

- `request_operation` maps to the finding's operation in the table; **and**
- `request_object_id` equals the assertion's `target_object_id`.

Old artifacts lack both fields, so they never count. Their digests do not change.

## The narrower guardrail

This replaces "strike evidence never moves a finding toward pass" (`with_strikes`
and `GuardrailError`):

> A strike can move a finding toward `pass` **only** through a counting denial,
> and only where the probe rules, given that denial, would pass it. Every other
> strike result is context, or makes the finding stricter.

How it is enforced, in `fns.verify.verdict`:

1. Judge each finding twice: once with no strike evidence (`baseline`), then
   with the counting denials (`with_counting`). Strike successes and context
   then apply to the result, as today.
2. If `with_counting` ranks looser than `baseline`, then **all** of the
   following must hold, or the verifier raises `GuardrailError`:
   - at least one counting denial exists for the item;
   - all of conditions 1 to 5 hold, checked again on the observation;
   - the finding's new supporting evidence includes that denial.
3. A finding's verdict can never rise above what the probe rules allow, given
   the counting denial in the observed-denial slot. That is because the strike
   enters `judge` as an input; it is never applied afterwards.

`fns verify` derives every verdict again from the artifacts, so a forged or
edited observation that lacks condition 1, 2, 3, 4 or 5 does not count. The
check then shows the mismatch (exit 5), as it does today for a tampered artifact.

## What moves, and why

### Committed goldens: none

- **`tests/golden/prove-verdicts.json`**: no change. It is the probe-only
  baseline of four FIXTURE runs (`demo-prove`, `lab-run-1/2/3-prove`), with no
  strike evidence, and `judge` is unchanged when there are no strikes.
- **`tests/golden/lab-run-*-mutate.digest`, report goldens and
  `fixtures/strike-demo`**: no change. All of them are FIXTURE.
- **Assertion digests**: no committed file changes, because no `assertions.json`
  is committed. `target_object_id` is omitted when empty, but freeze fills it from
  now on, so a new run's assertion digest differs from an old run's. The goldens
  above hold verdicts and decisions, not assertion digests, so they are
  unaffected. The build re-runs them to confirm this.

### Tests that change

| Test | Today | After |
| --- | --- | --- |
| `tests/prove/test_after_strike.py::test_denials_change_no_decision_and_only_add_context` | every golden plus synthetic denials: nothing moves | **Same assertions, kept.** The goldens are FIXTURE, so condition 1 already keeps every denial as context. Renamed `..._in_fixture_mode`, docstring narrowed |
| `tests/prove/test_after_strike.py::test_successes_never_move_a_finding_toward_pass` | unchanged | unchanged |
| `tests/prove/test_verifier_edges.py::test_strike_evidence_never_loosens_a_verdict` | property: "a denial changes nothing" | Split in two. (a) The same property for every non-counting observation, with hypothesis now also drawing mode, status, strike, request operation and object ID. (b) A new property: a finding moves toward `pass` only when a counting denial exists **and** `judge` given that denial passes it |
| `tests/test_runbook_m4_live.py` (D7 says "exit 3") | expects exit 3 | expects the table below |

### New tests

- **The LIVE matrix.** This is a unit test at verifier level, on the lab-run-2
  assertion set. It is relabelled `LIVE` in memory and hardened by the model:
  the four application items get `modeled_outcome` `denied` and no paths, like
  `fns mutate --harden` gives. Expected:

  | Item | Strike | Before B | After B | Why |
  | --- | --- | --- | --- | --- |
  | `application:id-verifier credentials/update` | D-2 denied 403 | `inconclusive`, `not-assessed` | **`pass`**, `verified` | counting denial, no path, no open surface |
  | `application:sp-fns-scout credentials/update` | D-3 denied 403 | `inconclusive` | **`pass`** | the same |
  | `application:id-verifier owners/update` | D-4 denied 403 | `inconclusive` | **`pass`** | the same |
  | `application:sp-fns-scout owners/update` | D-5 denied 403 | `inconclusive` | **`pass`** | the same |
  | `directory:tenant applications/credentials/update` | D-2 denied 403 | `inconclusive` | `inconclusive`, D-2 as context | condition 4: one app is not every app |
  | `directory:tenant roleAssignments/write` | none | `inconclusive` | `inconclusive` | condition 5 (SD3) |

  The resulting inconclusive count is 2 against `max_inconclusive: 2`, so the
  exit is 0. This holds only if the live snapshot has no open surface for the
  application items. lab-run-2 and lab-run-3 have none, but lab-run-1 had
  `pim-eligibility` open. With an open surface, the four items stay
  `inconclusive` ("denied (strike), but not collected: pim-eligibility") and the
  exit is still 3.
- **One negative row per condition.** Each row starts from the matrix and breaks
  one thing, and the item must stay as it was:
  - FIXTURE mode;
  - D-1;
  - a before-harden strike;
  - S4;
  - status 401, 400, 404 or none;
  - a gate denial;
  - the operation or object ID of another item;
  - an observation without the new fields (an old artifact);
  - `roleAssignments/write`;
  - an open surface;
  - an unrefuted path (it stays `fail`);
  - a probe allowed alongside the denial (it stays `fail`).
- **A forged observation.** An artifact edited to add the fields or flip the mode
  fails `fns verify` with exit 5.

### Docs that change

- `docs/runbooks/m4-live-run.md` D7: the expected-verdict table above, with exit
  0 if no surface is open and exit 3 otherwise. The two cases are told apart by
  the reason text.
- `docs/THREAT-MODEL.md`: "Strike evidence only tightens" becomes the narrower
  guardrail.
- `docs/ARCHITECTURE.md`: line 112 changes the same way.
- `docs/milestones/M4-strikes-plan.md`: the D6 section.
- STATUS, DECISIONS and CHANGELOG.

## Build order, once approved

One PR, about 400 lines with tests:

1. Model fields: `StrikeObservation.request_operation` / `request_object_id`
   and `Assertion.target_object_id`, all omit-empty. Then the schema regenerates.
2. `fns.prove.strikes` copies both request fields from the planned write.
   `fns.prove.freeze` records the target object ID.
3. `fns.verify.verdict`:
   - `COUNTING` (the table above) and `counting_denial(o, a)`;
   - `judge(a, obs, contract, strikes=())`, where a counting denial combines
     into the observed-denial slot;
   - `with_strikes`, keeping successes and context only;
   - the two-judgement `GuardrailError` check.
4. `fns.verify.main.build` passes the assertion's strikes to `judge`.
5. The tests, then the docs above.

`uv run poe check` must pass, including `lint-imports`: the verifier must still
import nothing from `fns.strike`.

## Decided

- **403 only** (Daniel, 2026-11-27). The strike engine records 401 and 403
  alike as `denied`, but only a 403 counts. A 401 stays `unknown`, as it does
  for the probes (V5).

## Open points for Daniel

1. **The tenant-wide item.** Should `directory:tenant applications/credentials/update`
   count from D-2? This plan says no: one app is not every app. Saying yes would
   make the gate exit 0 with one item fewer, but would claim more than the
   evidence.
2. **The PIM surface.** If the live snapshot leaves `pim-eligibility` open, the
   gate still exits 3. Should the runbook make collecting it a precondition of
   session D?
