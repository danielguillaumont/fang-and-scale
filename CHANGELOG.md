# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, a minor
version may change file formats; each change is listed here.

## [Unreleased]

## [0.1.0] - not tagged yet

The first release: contracts, the reach model, read-only probes with signed
evidence, harden and mutation testing in the model, the strike engine, and the
reports. M1, M2 and M3 ran live against the lab tenant. Everything from M4 on is
built and tested offline only (see "Not in 0.1.0").

### Contracts and scope

- Contract files (`*.fns.yaml`, schema v2): `must_not_reach` and `must_still_do`
  items on resources, the directory, applications and service principals, with
  budgets and `on_inconclusive`.
- `fns scope check` and the scope gate. Every Azure and Graph call goes through
  it; it denies by default, pins the tenant, and checks targets, URLs and
  expiry. Data-plane reads for `prove` are bound to their resource and to the
  pinned principal.
- Azure CLI credentials pinned to the scope tenant.
- JSON Schemas for every file format, committed in `schemas/` and checked for
  drift (`fns schema`).

### Scout and the reach model

- `fns scout`: a read-only, gated ARM and Graph collector. It covers role
  assignments, definitions and deny assignments, Graph app roles, owners, group
  membership, PIM eligibility, and Key Vault and storage settings. `--record`
  writes sanitized fixtures.
- `fns contain`: the reach engine. It models Azure RBAC with segment-wise scopes
  and deny assignments, a principal closure over the PLAN's escalation
  primitives, vault access policies, eligibility, and application credential
  and owner paths. Each finding gets labelled paths and an evidence rung, and
  anything not modeled is `inconclusive`, never a pass.
- Recorded lab runs `fixtures/lab-run-1` to `lab-run-3`, replayed as regression
  tests. `fns demo` replays them; it is labelled `FIXTURE` and makes no network
  call.

### Prove and verify

- `fns prove`: it freezes assertions before any probe and runs gated,
  journaled probes. With `--live`, the probes run as the pinned test identity.
  The run directory is then handed to a separate verifier process that holds no
  credentials.
- `fns verify`: integrity checks on the frozen assertions, the read-only
  journal and the content-addressed artifacts. It applies the verdict rules and
  signs the bundle with DSSE: an offline test key, or Sigstore keyless with
  the `sigstore` extra. A failure exits 5.
- Denied probes that settle nothing are kept with their finding as `context`
  evidence, which never changes a verdict.
- `fns prove --after-strike <dir>`: the D-1 to D-5 results of a strike run after
  harden. A denial is added as context. A success fails the finding. No finding
  can move toward `pass` because of a strike, and tests re-run every prove
  golden to check that.

### Harden, record and detections

- `fns harden` maps the lab Terraform to snapshot grants. It searches for the
  smallest removal that makes the contract pass in the model, and writes a diff
  that it never applies.
- `fns record`: `must_still_do` items from Activity, audit, Key Vault and blob
  log rows.
- `detections/`: KQL detection rules as code, with structural lint, coverage,
  and sample rows run by a small KQL evaluator (`fns detections check`).
  `fns detections export` renders them for Sentinel.
- `fns mutate`: five defence mutation operators, scored against a contract.
  Survivors are explained with the reasons the model added.

### Strikes (built offline; not run live)

- A write gate for `fns strike`. It allows listed write forms only, to lab
  targets only, with body allowlists. Its hard denylist no scope can lift.
  There are negative and fuzz tests for every rule.
- `fns strike plan | run | cleanup`, for S1 to S3 before harden and D-1 to D-5
  after:
  - each plan has a sha256 hash, and the operator approves that hash
    (`--approve`);
  - the plan expires after 1 hour, and a run refuses to start if the pre-state
    has changed;
  - each write is journaled before and after;
  - every undo runs in a `finally`, and a separate read-only identity verifies
    the result;
  - cleanup is driven by the journal;
  - secrets are stripped inside the transport.
- Two-identity live sign-in from two Azure CLI profiles, and a strict fixture
  replay (`fixtures/strike-demo`).

### Reports and CI

- `fns report`: one self-contained HTML page. It shows coverage first, then the
  reach graph (vendored Cytoscape, pinned by its SRI hash, under a CSP), the
  findings with an evidence-ladder column, the proof bundle, strike runs,
  detection results per strike, and mutation.
- `fns comment` and a composite GitHub Action for contain, prove, mutate and a
  sticky pull-request comment.
- CI on Ubuntu and Windows, CodeQL, and a Sigstore production signature of the
  recorded M3 replay on every push to `main`.

### Lab

- `lab/`: Terraform for the lab tenant: the identities, the vault, two storage
  accounts, the rendered scope and contract, an optional budget alert, an
  optional lab group, optional monitoring (workspace, Sentinel, diagnostic
  settings, the rules), and an optional strike block. Every optional part is
  off by default.
- Runbooks for every live session in `docs/runbooks/`.

### Not in 0.1.0

- M4 sessions A to D have not run live (`docs/runbooks/m4-live-run.md`), so no
  strike, detection result or after-harden prove comes from a real tenant yet.
- S4 (the escalated sign-in and the marker role) waits for its own decision.
- `harden --apply` is not built: you apply the diff yourself.
- Not published to PyPI. Install from a Git tag (`docs/QUICKSTART.md`).

[Unreleased]: https://github.com/danielguillaumont/fang-and-scale/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/danielguillaumont/fang-and-scale/releases/tag/v0.1.0
