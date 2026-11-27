# Threat model

What happens when a piece Fang & Scale relies on is hostile: the tool itself, a
fixture, a scope file, a contract, the tenant's own data, a run directory, or a
pull request. For each, the doc covers what an attacker could try, what stops
it, and **what does not**. The boundaries themselves are drawn in
[ARCHITECTURE.md](ARCHITECTURE.md). To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## What is worth protecting

| Asset | Why it matters |
| --- | --- |
| The tenant the tool is pointed at | It writes (strikes) and reads with real credentials |
| The operator's Azure CLI login | Any code in the `fns` process can reach it |
| The truth of a verdict | A false `pass` is worse than no tool (CLAUDE.md rule 4) |
| Signed evidence bundles | Other people rely on them without re-running anything |
| Personal and tenant identifiers | Fixtures and reports are shared |

## Assumptions

- The operator runs `fns` against a tenant they own or are authorized to test,
  and signs in to it on purpose.
- The executor's lab identities have RBAC on the lab only. That is the limit that
  holds even if everything in this repository fails (PLAN section 9).
- Python, the OS, and GitHub-hosted runners are not compromised.

## 1. A malicious tool

*A compromised dependency, a malicious commit to this repository, or a tampered
release download.*

**What it could do.** Code running in the `fns` process can do anything the
operator's login can do. The scope gate is a Python object in the same process,
so hostile code can simply not call it.

**What stops it:**
- **Dependencies.** `uv.lock` pins every dependency with its hash. CI and the
  release install with `--locked`. Dependabot proposes updates as reviewed PRs,
  and CodeQL scans every PR.
- **CI.** Third-party actions are pinned by commit SHA, and the workflow tokens
  are read-only by default.
- **This repository.** `main` has branch protection (no force pushes, no
  deletion), and CODEOWNERS names the owner as the reviewer of every file.
  Reviews are not *required*: there is one maintainer (Open gaps).
- **Releases.** A release is a draft that a person publishes. It ships with a
  CycloneDX SBOM and `SHA256SUMS`, and is built from a tag after the full check.
- **The executor.** Its identities hold lab RBAC only, so even unchecked code
  acting as them reaches only the lab.

**What does not:**
- **The gate is not a sandbox.** It stops *this* code from leaving the scope. It
  cannot stop other code in the same process. Do not run `fns` with a login that
  can reach production.
- **`SHA256SUMS` sits in the same release as the files it covers**, so it shows
  a download was not corrupted, not who built it. A Sigstore attestation of the
  release files would show who built them; it is not done yet (Open gaps).
- **The verifier runs on the same machine as the prover.** It has no credentials
  and imports no prover code, but a fully compromised machine controls both.

## 2. A malicious fixture

*A fixture set under `fixtures/`, a `--fixture` path, or one sent in a PR.*

**What it could try:**
- pass itself off as a live recording;
- make the tool call the network;
- inject markup into the report;
- carry real identifiers into the repository;
- exhaust memory.

**What stops it:**
- **Labelling.** A set must say `"label": "FIXTURE"` in its manifest, or it is
  refused. Every line, file and bundle built from it is marked `FIXTURE`, and
  FIXTURE and LIVE never mix in one run: the verifier checks the mode of each
  artifact.
- **No network.** `FixtureTransport` never opens a connection. A request with no
  recorded response is an error; replay never invents an empty result.
- **No injection.** Strings from fixtures are tenant strings, escaped in the
  HTML report and in the PR comment (section 5).
- **No real identifiers.** `tests/fixtures/test_no_real_ids.py` fails on
  non-placeholder tenant IDs and real email addresses in committed fixtures. The
  sanitizer's ID map is never committed.

**What does not:**
- **A fixture can claim anything about its fake tenant.** "FIXTURE" means "not
  observed": a fixture's verdicts are evidence about the fixture, never about a
  tenant. `fns demo` says so on every line.
- **JSON fixture files have no size limit** (YAML files do: 1 MiB). A huge
  `exchanges.json` can exhaust memory on the machine replaying it (Open gaps).

## 3. A malicious scope file

*`scope.yaml` edited by someone other than the operator, or sent in a PR.*

**What it could try:**
- point the tool at another tenant;
- widen what it reads;
- add strike targets that are not lab objects;
- never expire.

**What stops it:**
- **Tenant pinning.** The signed-in tenant, the scope's tenant and each call's
  tenant must be the same, or nothing runs (exit 4). A scope file cannot sign
  anyone in.
- **Expiry.** `expires_at` is required and checked on every call. The `strike:`
  block has its own expiry, and a strike plan expires after 1 hour at most.
- **Fixed verbs.** `scout`, `contain` and `harden` are read-only verbs, and the
  gate refuses a write on them whatever the scope lists. Only `prove` may use
  the data plane.
- **Writes are limited.** A write goes through the **hard denylist**, which no
  scope can lift (directory roles, permission grants, ARM authorization,
  logging and detection, Microsoft first-party objects). Then it must match one
  exact write form and a body allowlist.
- **Strike targets are checked as lab objects:**
  - ARM targets are exactly one vault or storage account and must carry the lab
    tags (checked when planning);
  - Graph targets must carry the lab tags and the display name Terraform gave
    them (checked live by the gate before the first write);
  - a first-party object is refused when the scope is parsed.
- **A person approves the plan.** `fns strike run` needs `--approve` with the
  hash of `plan.json`, and the runbook prints the plan in full before asking for
  it.
- **Strict YAML.** Duplicate keys, anchors and aliases, multiple documents and
  files over 1 MiB are all refused. A `tenant_id` written twice is an error, not
  "the last one wins".

**What does not:**
- **If the operator is signed in to a production tenant and the scope names it,
  reads run there.** Pinning checks that the two agree, not that the tenant is a
  lab. The scope's purpose is to make that choice explicit and reviewable.
- **Lab tags are a label, not an authorization.** Anyone who can write to a
  production object can tag it. The executor identities' lab-only RBAC is what
  makes such a target unreachable.

## 4. A malicious contract

*A `*.fns.yaml` weakened in a PR.*

**What it could try:**
- drop `must_not_reach` items;
- raise budgets;
- set `on_inconclusive: warn`;
- widen what the tool calls.

**What stops it:**
- **A contract cannot widen any call.** The gate reads only the scope. A contract
  says what to check, never what to touch.
- **The PR comment compares with the base branch**, so a PR that removes findings
  shows it.
- **Unmodeled semantics never pass.** `inconclusive` is never `pass`, and the
  report leads with coverage, not a score.

**What does not:** a reviewer who approves a weakened contract. Contracts are
code, and the tool cannot tell a deliberate scope change from an attack. On a
team, require code-owner review on contract files.

## 5. Hostile tenant data

*Display names, descriptions, `nextLink`s and log rows, chosen by anyone who can
edit an object in the tenant.*

**What it could try:**
- script injection in the HTML report;
- mentions or Markdown injection in the PR comment;
- redirecting a paged call to another host;
- instructions aimed at an LLM (PLAN section 9).

**What stops it:**
- **The report.** Every tenant string is HTML-escaped. The graph data is
  embedded as escaped JSON and shown with `textContent`. A CSP allows only the
  vendored, hash-pinned Cytoscape.
- **The PR comment** escapes `@`, `|`, `<`, backticks, brackets, emphasis and
  newlines in one pass.
- **Paging.** A `nextLink` is checked by the gate like any URL. If it is denied,
  the collector fails and discards the earlier pages.
- **No LLM.** No language model reads tenant data in 0.1.0. When one does (M6
  bake-off), it sits on the proposer side, with no write credentials and no
  route to the verifier.

Tests: `tests/test_report_html.py`, `tests/test_report_strikes.py`,
`tests/test_action.py`, `tests/scope/test_gate_fuzz.py`.

**What does not:**
- **Terminal output is not cleaned of control characters.** Rich drops some
  (BEL) but passes ESC through. A display name with escape sequences in it could
  recolour, hide or overwrite lines that `fns contain` prints in a terminal. The
  HTML report, the JSON files and the PR comment are not affected (Open gaps).
- **Escaping is not judgement.** A hostile name that reads as a real one ("Owner
  approval required") is shown faithfully, as data.

## 6. A forged or tampered run directory

*Someone edits `assertions.json`, the journal or an artifact, or writes a whole
run directory by hand, to get a `pass`.*

**What stops it:**
- **Integrity checks.** The verifier re-hashes each artifact and checks it
  against the journal. It refuses evidence recorded before the freeze, and
  evidence from another run or mode. It re-derives every verdict and never
  copies one. Any failure exits 5 and writes no bundle.
- **Re-checking.** `fns verify check` re-does all of that on a finished run,
  plus the signature and every subject digest.
- **Strike evidence only tightens.** It cannot move a finding toward `pass`
  (`GuardrailError`), and a test re-runs every prove golden to check that.

**What does not:**
- **Consistency is not truth.** A careful forger who writes a consistent run
  directory and signs it with the offline test key gets a bundle that verifies.
  The test key proves integrity only, and says so (`TEST SIGNATURE`).
- **A Sigstore signature checked with `--identity` and `--issuer`** shows *who*
  signed: for production, this repository's `prove-sign` workflow on `main`. It
  still cannot show that the tenant really answered that way. Trust a LIVE
  bundle as far as you trust the identity that signed it.
- **The journal is a SQLite file**, opened read-only by the standard library. A
  hostile database file relies on SQLite's own parser being safe.

## 7. A hostile pull request

*Code or files from a fork, run by this repository's workflows.*

**What stops it:**
- **`blast-radius`** runs on fixtures only, with no Azure login and no secrets.
  On a fork its token is read-only, so it cannot comment.
- **`prove-sign`** skips fork and Dependabot PRs. Production signing runs only
  on a push to `main`.
- **First-time contributors** need approval before their workflows run.
- **No script injection.** Values reach `run:` steps through `env`, never through
  `${{ }}`, and a test enforces that.
- **`release`** runs only on a `v*` tag, which only a maintainer can push.

**What does not:**
- **The blast-radius result is computed by the PR's own code.** On a
  `pull_request` event, the PR's own version of the workflow, the action and the
  tool run. A hostile PR can make that check pass or its comment say anything.
  Review the diff, not the comment.
- **Nothing forces CI to pass before a merge** (Open gaps).

## Open gaps

The protections these gaps need are not built yet. Each needs a decision before
it is.

| Gap | Effect | Possible fix |
| --- | --- | --- |
| Terminal output keeps ESC and other control characters from tenant strings | A crafted display name can hide or rewrite lines in a terminal | Strip C0 and C1 control characters from tenant strings before printing (planned: queue item 10) |
| JSON inputs (fixtures, run directories, reports) have no size limit | A huge file can exhaust memory on the machine reading it | A size cap like the YAML loader's 1 MiB, sized per file type |
| Release files are not attested | `SHA256SUMS` shows integrity, not who built them | A Sigstore build attestation in `release.yml`, which needs `id-token: write` |
| No required status checks on `main` | A PR can merge with CI red | The one command in `docs/PUBLIC-READINESS.md`, "Require CI to pass" |
| No required reviews on `main` | One account can change the gate, the verifier or a contract alone | Required code-owner review, once there is a second maintainer |
