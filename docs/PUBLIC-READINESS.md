# Public-readiness audit (2026-11-26)

## Status: PUBLIC (2026-11-26)

The owner made the repository public on 2026-11-26, after this audit. Settings
read back through the GitHub API the same day:

| Setting | State |
| --- | --- |
| Visibility | public |
| Secret scanning | enabled |
| Push protection | enabled |
| Dependabot alerts | enabled |
| Dependabot security updates | enabled |
| Private vulnerability reporting | enabled |
| Code scanning default setup | not configured (correct: `codeql.yml` is the advanced setup) |
| Branch protection on `main` | classic rule: force pushes blocked, deletion blocked. **No required status checks yet**: see "Require CI to pass" below |
| Workflow token | read-only; cannot approve pull requests |
| Fork PR workflows | approval required for first-time contributors |
| Automatically delete head branches | off (settings step 4, optional) |

Owner decisions, as reported by the owner:

- **Decision 2 (lab names):** option a. The lab is torn down (`rg-fns-lab`
  destroyed), and the next rebuild gets a new random suffix. `tiin02` remains in
  the fixtures and history as a recording of endpoints that no longer exist.
- **Decision 3 (school email):** option a. New commits use the GitHub noreply
  address; history is unchanged.
- **Decision 1 (exact-ID check)** and **decision 4 (Claude Code working files)**:
  no outcome recorded here.

Since then:

- **CodeQL** runs on pull requests, on `main`, weekly and by hand (#46, #50).
- **Sigstore production signing** is on for pushes to `main` (V3, #49). The
  first production signature is Rekor log index 4138528019, for commit
  `2a176dc`. See README, "Verify a signed result".
- **A Sigstore verification failure now exits 5** instead of printing a
  traceback (#51).

## Require CI to pass (optional; not applied)

Branch protection on `main` has no required status checks yet. These are the
checks that run on every pull request, with the names GitHub uses for them
(read from the check runs of #51):

| Check name | Workflow | Reported by | Require? |
| --- | --- | --- | --- |
| `check (ubuntu-latest)` | `ci` | GitHub Actions (app 15368) | **yes**: ruff, mypy, import boundaries, schema drift, pytest |
| `check (windows-latest)` | `ci` | GitHub Actions | **yes**: the same on Windows (about 5 minutes) |
| `lab (terraform fmt + validate)` | `ci` | GitHub Actions | **yes**: the lab Terraform, no credentials |
| `codeql (python)`, `codeql (actions)` | `codeql` | GitHub Actions | optional: they pass even when they raise an alert. Use a code scanning merge rule to gate on alerts instead |
| `CodeQL` | code scanning results | GitHub Advanced Security (app 57789) | no: it is the alert summary, not a job |
| `blast radius (fixture)` | `blast-radius` | GitHub Actions | no: it reports and is meant not to gate. Its comment step fails on fork PRs (read-only token) |
| `prove and sign (Sigstore)` | `prove-sign` | GitHub Actions | no: on PRs it signs on Sigstore staging, an external test service, and it skips fork and Dependabot PRs |

Not PR checks: `prove-sign` on a push to `main` (the production signature) and
the weekly CodeQL schedule.

To require the three `ci` checks, run this **one** command. It works in
PowerShell and in bash:

```
'{"required_status_checks":{"strict":true,"checks":[{"context":"check (ubuntu-latest)","app_id":15368},{"context":"check (windows-latest)","app_id":15368},{"context":"lab (terraform fmt + validate)","app_id":15368}]},"enforce_admins":false,"required_pull_request_reviews":null,"restrictions":null,"allow_force_pushes":false,"allow_deletions":false}' | gh api -X PUT repos/danielguillaumont/fang-and-scale/branches/main/protection --input -
```

What it does:

- `PUT .../protection` replaces the whole classic rule, so the command restates
  what is on now: force pushes and deletion stay blocked, there are no required
  reviews, and every other option stays off.
- `app_id` 15368 is GitHub Actions. Only a check reported by Actions under that
  name counts, so another app can't satisfy it.
- `strict: true` means a PR must be up to date with `main` before it merges.
  Run `gh pr update-branch <n>` when `main` has moved. Use `false` if that gets
  in the way.
- `enforce_admins: false` leaves you, as admin, a deliberate bypass
  (`gh pr merge --admin`). Set it to `true` if the rule should bind you too.
- Skipped jobs count as passed, and none of the three is ever skipped.

Read it back with
`gh api repos/danielguillaumont/fang-and-scale/branches/main/protection/required_status_checks`.
`tests/test_public_readiness.py` checks that the command's JSON parses and that
its three names are exactly the jobs `ci.yml` runs on pull requests.

The audit as written before the change of visibility follows, unchanged except
where marked *(updated)*.

---

Audit before making `danielguillaumont/fang-and-scale` public. Nothing here
changed visibility, rewrote history or force-pushed. Every fix went through its
own PR with CI green.

**Recommendation: GO, once you have done the three owner checks in "Needs your
decision" (about 15 minutes) and turned on the settings in "GitHub settings".**
No secret, credential or real tenant identifier was found in any commit, branch,
tag, PR head, PR text or comment. The one personal item in history is your
school email address in commit metadata. It can't be removed without a
history rewrite, so only you can accept it.

## a. Secrets and identifiers in the full history

Scope: every commit reachable from any branch, tag or `refs/pull/*` head (163
commits when scanned; the PR heads added no commits of their own), every PR and
issue title and body, every issue and review comment (29), and releases (none).

### gitleaks 8.30.1, `--log-opts=--all`

3 hits, all false positives:

| Commit | File | Rule | What it is |
| --- | --- | --- | --- |
| `8f5c693` | `tests/test_mutate.py:56` | generic-api-key | the mutant name `listkeys:<storage account>` |
| `3cf1285` | `src/fns/verify/signing.py:83` | generic-api-key | the type annotation `key: Ed25519PrivateKey` |
| `1fba93c` | `tests/fixtures/test_sanitize.py:100` | jwt | a synthetic JWT: `{"alg":"RS256"}`.`{"sub":"1234567890"}`.`signature-bytes` |

Fixed (#44): `.gitleaks.toml` keeps the default rules and allowlists exactly those
three strings. With it:

- full history and the tracked tree scan clean;
- a random `ghp_…` canary token is still caught.

The untracked, gitignored `lab/terraform.tfstate` and `.backup` do hold lab
secrets. They were never committed: no path matching `tfstate`, `scope.lab.yaml`,
`_idmap.json`, `.env`, `*.pem`, `*.pfx`, `*.key` or `*.tfvars` appears in any
commit.

### Identifiers

| Search | Result |
| --- | --- |
| GUIDs that are neither placeholders (`00000000-0000-4000-8000-…`) nor defined in `src/` | **7, none real.** `3f2504e0-4f89-…` (the textbook example UUID) and `6ba7b810-9dad-…` (an RFC 4122 namespace variant) are in `tests/fixtures/test_sanitize.py` and `test_replay.py`. `a1b2c3d4-…` and `ABCDEF01-…` are in tests. `1bfefb4e-…-73c6d2b2e8db` is a wrong early value of Graph's well-known `Application.ReadWrite.All` app-role ID, in `src/fns/fixtures/wellknown.py` (first seen in `1fba93c`, fixed later; see FINDINGS) |
| `seclab` | **0** files in any commit |
| `outlook.com` | **0** |
| any email address in file contents | the GitHub noreply address (`pyproject.toml`), Microsoft's fictional `contoso.com` and `contoso.onmicrosoft.com` (sanitizer tests), `user1@`/`user2@`/`usern@example.invalid` (sanitized fixtures and the sanitizer), and `user:pw@management.azure.com` (a URL-with-credentials rejection test). No personal address |
| `tiin02` | **22 files**, first in `d9efc7a` (`fixtures/lab-run-1/exchanges.json`), now in `fixtures/lab-run-{1,2,3}/`, `docs/DECISIONS.md` and 10 test files, plus the blast-radius bot comments on PRs #15–#43. It is the lab's random resource-name suffix (`kv-crown-tiin02`, `stinvoicestiin02`, `stpayrolltiin02`); see decision 2 below |

Not compared: the real IDs themselves. Reading `_idmap.json` and `scope.lab.yaml`
was refused in the audit session, correctly, since they hold your real email and
IDs. The GUID search above would catch any real object, tenant or subscription
ID. A direct check against your own values is owner check 1.

Nothing needed fixing in the current tree.

## b. Commit author and committer identities

| Identity | Where | Count |
| --- | --- | --- |
| `danielguillaumont <g…@sheridancollege.ca>` | author and committer of every non-merge commit, and the tagger of `m1`, `m2`, `m3` | 240 entries |
| `Daniel Guillaumont <g…@sheridancollege.ca>` | author of the PR merge commits | 43 |
| `GitHub <noreply@github.com>` | committer of the PR merge commits | 43 |

**Flag: a personal (school) address, not a noreply address, is on every
commit.** It becomes public with the repository. Owner decision 3 covers it.

## c. Policy files (fixed, #45)

- `SECURITY.md`:
  - private reporting through GitHub's private vulnerability reporting;
  - what is in scope (scope-gate bypass, unapproved writes, verifier acceptance
    of tampered or overstated runs, leaks, report injection, workflows) and what
    is out of scope (Microsoft platform issues go to MSRC, findings in your own
    tenant, the deliberately over-privileged lab);
  - use only on tenants you own or are authorized to test.
- `CONTRIBUTING.md`: setup, `poe check`, the rules every change keeps, PR
  conventions.
- `.github/CODEOWNERS`: `* @danielguillaumont`.
- README: an "Authorized use only" box under the tagline.

Tests keep all four in place.

## d. Dependabot and CodeQL (fixed, #46)

- **`.github/dependabot.yml`:** uv, GitHub Actions and the lab's Terraform
  providers, weekly, one grouped PR per ecosystem.
- **`.github/workflows/codeql.yml`:**
  - analyses `python` and `actions` with the `security-extended` queries, on PRs,
    on `main` and weekly;
  - permissions are `actions: read`, `contents: read` and `security-events: write`,
    with the action pinned to a commit SHA;
  - code scanning is not available on a private free repository, so the job is
    **skipped while the repository is private**. It runs on its own once the
    repository is public.

### GitHub settings to turn on right after making it public

1. **Settings → Code security** (the page may be titled "Advanced Security"):
   - **Private vulnerability reporting:** Enable. `SECURITY.md` points to it.
   - **Dependency graph:** Enable (on by default for public repositories).
   - **Dependabot alerts:** Enable. **Dependabot security updates:** Enable.
   - **Secret Protection / secret scanning:** Enable, then **Push protection:**
     Enable.
   - **Code scanning:** leave **Default setup off**. `codeql.yml` is the advanced
     setup, and the two conflict. After the first run on `main`, check the Security
     tab shows CodeQL results.
2. **Settings → Rules → Rulesets → New branch ruleset**, target `main`, enforcement
   Active (or the classic **Branches → Add branch protection rule**):
   - **Require a pull request before merging**, with required approvals **0**. You
     are the only maintainer, and GitHub does not let you approve your own PR.
   - **Require status checks to pass:** `check (ubuntu-latest)`,
     `check (windows-latest)`, `lab (terraform fmt + validate)`. Also tick
     "Require branches to be up to date"; `gh pr update-branch` keeps that cheap.
     Add `codeql (python)` and `codeql (actions)` after they have run once.
     `blast radius (fixture)` reports and is not meant to gate.
   - **Block force pushes** and **Restrict deletions**.
   - Leave the bypass list empty, or only "Repository admin" for emergencies.
3. **Settings → Actions → General:**
   - **Fork pull request workflows from outside collaborators:** "Require approval
     for all outside collaborators" (at least "for first-time contributors").
   - **Workflow permissions:** keep "Read repository contents" (already set) and
     leave "Allow GitHub Actions to create and approve pull requests" off (already
     off).
4. **Settings → General:** turn on **Automatically delete head branches**.
   Optionally delete the 22 merged remote branches; their commits stay on `main`.
5. **Your GitHub account → Settings → Emails:** turn on **Keep my email addresses
   private** and **Block command line pushes that expose my email**. Then, in this
   repository:
   `git config user.email 181521129+danielguillaumont@users.noreply.github.com`.

Already fine: no Actions secrets, variables or environments exist, and the default
workflow token is read-only. Every third-party action is pinned to a commit SHA
(tested). `blast-radius` uses `pull_request`, never `pull_request_target`, so fork
PRs get no write token and no secrets. Only `prove-sign` can mint an OIDC token,
and only on `main` (tested). *(updated, #49: also on pull requests from branches
of this repository, for Sigstore staging only; never for forks or Dependabot,
never via `pull_request_target` or `workflow_run`.)*

## e. README review (fixed, #47)

| Was | Now |
| --- | --- |
| "finds **every** path to the boundary" | the escalation paths **its rules model**; anything it cannot model or probe is `inconclusive`, never a pass |
| "proves the result with signed evidence" | "checks the result with read-only probes and signed evidence" |
| no statement of maturity | "a personal research project: one maintainer, one lab tenant, no release yet" |
| `fns harden` "finds the smallest Terraform removal" | an exact search, smallest set first, over the grants it can map in `lab/*.tf`; it writes a diff and plan hash and never applies |
| "the highest rung it reached" | the highest rung its supporting evidence reached; context never raises coverage |
| "Production Sigstore needs approval" | stays off until the repository is public |
| "The gate is fuzzed with Hypothesis" | negative tests per rule plus Hypothesis property tests |
| no trademark note | Microsoft trademark and non-affiliation note, plus links to SECURITY and CONTRIBUTING |

Kept on purpose, because it is the strongest material for a reviewer:

- "Mutation testing found a gap in our own contract";
- the Real vs. fixture table;
- rung 4 "never run in a workspace";
- the exit-code contract.

## Needs your decision

1. **Run the exact-ID check yourself (owner check 1).** It is the one search this
   audit could not do. From the repository root, with your real tenant ID,
   subscription ID and email to hand:

   ```powershell
   git grep -i -l -e <tenant-id> -e <subscription-id> -e <your-email> $(git rev-list --all)
   ```

   It must print nothing. Do the same for any object or app ID you know.
   Repeat it with `gh pr list --state all --json body`.
2. **The lab's resource names (`tiin02`).** Key Vault and storage account names
   are global DNS names (`kv-crown-tiin02.vault.azure.net`,
   `stinvoicestiin02.blob.core.windows.net`). Publishing them tells anyone where
   your lab's endpoints are. They hold only synthetic data. Anonymous blob access
   is off (`allow_nested_items_to_be_public = false`), but network access is open
   by default and shared-key access is enabled, so data needs Entra ID or the
   account keys. The options:
   - **a.** Destroy the lab before you publish (`uv run poe lab-down`), or move to
     a new suffix for M4. **Recommended:** the next lab gets fresh names, and the
     fixtures stay valid as recordings.
   - **b.** Accept it: the names are already in 22 files across history and can't
     be removed without a rewrite.
3. **Your school address in commit metadata.** It is on all commits and the three
   tags. The options:
   - **a.** Accept it, and switch to the noreply address for new commits (settings
     step 5). **Recommended**, given "do not rewrite history".
   - **b.** Rewrite history before publishing (`git filter-repo --mailmap`, then
     force-push and re-create the tags). This is only possible before the repo is
     public: afterwards, forks and caches keep the old commits. It breaks every
     existing SHA, including those quoted in docs, FINDINGS and the PR history.
4. **Claude Code working files.** These are visible and are not attribution
   (there are no co-author trailers or "Generated with" lines anywhere):
   - `CLAUDE.md` and `.claude/settings.json`;
   - `docs/PLAN.md` lines 3–4 ("lives in Daniel's Claude doc", "the repo copy
     that Claude Code reads");
   - `docs/OVERNIGHT.md`, and `docs/STATUS.md` written as reports to you ("Your
     two follow-up questions", "I stopped here, as asked");
   - three commit subjects that name Claude Code.

   They show how the project is run. Many people now publish this openly.
   Keep them, or move the working notes (`OVERNIGHT.md`, `STATUS.md`) to
   `docs/history/` and reword `PLAN.md` lines 3–4. The commit subjects stay
   either way.

## Smaller follow-ups (no decision needed)

- `blast-radius` on a **fork** PR: the comment step will fail, because fork PRs
  get a read-only token. The job does not gate merging, but it shows red on
  contributors' PRs. It could skip the comment when
  `github.event.pull_request.head.repo.full_name != github.repository`.
- Once public, the GitHub Actions run logs and the `prove-sign` artifacts become
  visible. They come from fixtures only (placeholder IDs, `FIXTURE` labels), so
  nothing changes.
- Sigstore production stays refused (`PRODUCTION_APPROVED = False`, decision V3)
  until the repository is public. After that it is a separate decision.
  *(updated: approved and done in #49.)*

## PRs from this audit and the M3 decisions

| PR | Change |
| --- | --- |
| #43 | Decision 1: denied probes attached to their findings as context. Verdicts, coverage and summaries are unchanged (baseline test); the four prove goldens are regenerated |
| #44 | Decision 3: TODO for `PIM_FREE_PLAN_IDS`. gitleaks configuration |
| #45 | SECURITY.md, CONTRIBUTING.md, CODEOWNERS, authorized-use notice |
| #46 | Dependabot and CodeQL |
| #47 | README wording for a public audience |
| this PR | This report |
