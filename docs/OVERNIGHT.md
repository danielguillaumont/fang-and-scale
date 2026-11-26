# Overnight run, 2026-11-26

Unattended run of the queue in the overnight brief. All ten items are done; this
file is the final step. No Azure call was made: no `az`, no `terraform apply`
or `destroy`. Everything below was built and tested against fixtures and mocks.

## Merged pull requests

Each PR was green on ubuntu and windows (plus `lab`, and from #15 on, `blast radius`)
before merging. CI was green on the first round every time. No PR is open and
no blocker was recorded, so there is no `docs/BLOCKERS.md`.

| PR | Merge | One line | Tests on main after merge |
| --- | --- | --- | --- |
| #7 | 495c074 | M2 spec (`docs/milestones/M2.md`) and the `.claude/settings.json` PR-workflow settings | 515 |
| #8 | 2bcc795 | M2 C2: reach engine as a fixed point, escalation rules (owner adds credential, AppRoleAssignment self-grant, roleAssignments/write, listKeys, Key Vault control-to-data), RBAC evaluation, contract semantics | 625 |
| #9 | 4b4d328 | M2 C3: `fns contain`, `fns demo contain`, ContainReport JSON, escalation paths with rung and coverage labels | 637 |
| #10 | 057f6c2 | M2 C1: Key Vault and storage settings collectors (mocked) and `docs/runbooks/m2-live-run.md` | 657 |
| #11 | 7dade90 | M3 offline: frozen assertions, `fns.verify` in a separate process, verdict rules, DSSE/in-toto signing with an offline TEST key, `fns prove`, `fns verify` | 729 |
| #12 | 9f26ea6 | M4 offline: least-privilege minimizer (`fns harden`), record mode (`fns record`), 9 KQL detection rules with lint and coverage tests | 764 |
| #13 | 82dc069 | M5: defence mutation testing (`fns mutate`), 5 operators, Terraform diffs round-tripped through the lever map | 774 |
| #14 | 1702093 | M5: static HTML report (`fns report`, `fns demo report`): coverage first, Cytoscape reach graph, proof and mutation | 780 |
| #15 | e4e0aff | M5: composite GitHub Action and `blast-radius` workflow that posts a sticky PR comment (fixtures only) | 788 + 1 Linux-only |
| #16 | 15f3ad7 | README overhaul: 90-second demo, mermaid architecture, evidence ladder, real vs. fixture, roadmap | 804 + 1 Linux-only |

The run went from 515 to 804 tests. The Linux-only test runs the action's bash
script; on Windows, `bash` resolves to WSL, so I ran that script by hand in Git
bash instead.

## Needs your review

Every item below is tagged `[NEEDS-DANIEL-REVIEW]` in `docs/DECISIONS.md` and was
called out in its PR. In each case I took the conservative option and kept going.

**Specs not approved yet:** `docs/milestones/M3.md` and `docs/milestones/M4.md` are
"drafted, not approved". The code follows them.

M2:

1. The reach engine uses a fixed point over facts with provenance, not NetworkX
   (M2.md said "Paths").
2. Unknown resource settings take Azure's default: shared key allowed, vault in
   RBAC mode.
3. `kv-control-to-data`: `vaults/write` counts as reaching secrets.

M3:

4. **E1.** A `must_not_reach` pass needs an observed denial, every path refuted,
   and no open surface. Because PIM eligibility is never collected, **no
   `must_not_reach` item can pass yet.** This is deliberate, but it is the biggest
   behavioural choice of the night.
5. **E2.** Escalation paths are not refutable. An indirect way is refuted only by
   a denied check of its own action.
6. **E3.** Live data-plane probes need a scope-gate change (plan first).
   `DataReadProbe` refuses until then.
7. **E4.** There is no "authorization-only" probe for writes, so writes reach rung
   2 at most.
8. **E5.** Offline signing uses an ephemeral key labelled TEST. The Sigstore path
   is written but has never run.
9. **E8.** The in-toto predicate type URI points at
   `docs/predicates/prove-v1.md` on GitHub.

M4:

10. **H1.** The minimizer only removes; it never narrows a role. A contract that
    needs read kept and write removed from one role gets "no proposal".
11. **H2.** The search is exact up to 4 levers, ties break lexically, and
    ambiguous grants stay unmapped.
12. **H6.** I propose moving four non-destructive strikes from M6 into M4 so the
    M4 gate can be observed. This is a PLAN change, and nothing is built.

M5:

13. A mutant is killed only by a new failing finding (inconclusive does not
    count), and a failing baseline cannot be scored.
14. `fns mutate` allows 0 survivors by default. `fns demo mutate` needs a
    repository checkout.
15. **Mutation finding.** The seeded contract misses 3 of 8 mutants on the
    hardened lab: listKeys on invoices, and the agent becoming an owner of
    `id-verifier` or `sp-fns-scout`. Owning `id-verifier` would let a compromised
    agent sign in as the verifier, which defeats the M3 trust boundary. Contract
    v1 cannot name a single application as a target, so this is a schema
    question for you.
16. The HTML report loads Cytoscape from cdnjs with SRI and a strict CSP,
    rather than vendoring it.
17. The GitHub Action is fixture-only: no OIDC, no live scout, no Sigstore.
18. Exit code 1 means both "invalid input" and "contract failed". The action
    works around this, but I propose a distinct code.

## What needs you and Azure next

In this order:

1. **`docs/runbooks/m2-live-run.md`.** This is the M2 live run, with exact
   PowerShell steps. It refreshes the lab, scouts with the settings collectors,
   and runs `fns contain`. The expected verdict table is in the runbook: 6
   critical, 2 inconclusive, exit 1.
2. **`docs/runbooks/m1-live-run.md`, the Directory.Read.All test.** Can the scout
   drop `Directory.Read.All`?
3. **Approvals before any further live work:**
   - M3 P5: live probes, the data-plane gate vocabulary and Sigstore in CI with
     OIDC;
   - M4 K4: record from real logs, harden, prove, then deploy the detections to a
     workspace;
   - H6: strikes in M4.

   There are no runbooks for these yet, because each starts with a plan you
   approve.
4. **v0.1 tag (M5 gate).** After the M2 live run agrees with the runbook table.

## Check first in the morning

1. **PR #15.** The comment the action posted on its own PR shows the
   `blast-radius` workflow working end to end: headline, findings table and
   mutation survivors, with the baseline taken from the base commit.
2. **The README mermaid diagram.** Open the README on GitHub and confirm it
   renders; I could not render it locally.
3. **`uv run fns demo report --fixture fixtures/lab-run-1`.** Open
   `.fns/report.FIXTURE.html`; I checked it in headless Edge, in light and dark
   mode.
4. **E1 and the mutation finding** (items 4 and 15 above). Both change what
   "green" can mean.
5. **PR #14 merge.** It was merged by hand. The helper's check watch returned
   before the Windows job finished, so I watched again and merged only after it
   passed. Nothing was skipped.
6. **The ship and commit helpers** live in the session scratchpad, not in the
   repo, and are not needed again.
