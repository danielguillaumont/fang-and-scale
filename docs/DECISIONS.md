# Decision log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-11-25 | Entra/Azure-first; AWS is a later adapter | Microsoft-heavy target roles; SC-200 alignment |
| 2026-11-25 | Absorb K9 ideas (coverage states, hypotheses, scope manifest); retire the K9 name | One complete flagship; k9 Security already sells Azure IAM analysis |
| 2026-11-25 | Module name Antivenom (not Defang) | Defang is an existing company |
| 2026-11-25 | Python only, SQLite, static report for v0.1 | Ship the loop before the infrastructure |
| 2026-11-25 | Workload/agent identities are the wedge | Less crowded than generic attack-path graphs |
| 2026-11-25 | poethepoet tasks in `pyproject.toml` (`uv run poe <task>`) instead of a Makefile | Dev on native Windows, CI on Linux; poe `cmd` tasks run without a shell |
| 2026-11-25 | `.gitattributes` `* text=auto eol=lf`; code writes files with `newline="\n"` | Committed schemas/fixtures must be byte-identical on Windows and Linux |
| 2026-11-25 | CI matrix ubuntu-latest + windows-latest; actions pinned by commit SHA | Catches path/newline/SQLite-locking bugs on the dev OS; supply-chain hygiene |
| 2026-11-25 | Rule 2 enforced by ruff `TID251` (Azure SDK imports only in `fns.adapters`, `fns.scope.credentials`) | Mechanical check instead of convention |
| 2026-11-25 | Rule 5 enforced by import-linter: `fns.verify` may not import `fns.harden`, `fns.strike`, `fns.adapters` (transitive) | Trust boundary checked from day one; empty `strike`/`harden` packages exist so the contract resolves |
| 2026-11-25 | `ExitCode` enum; not-implemented = 2 per M1 spec (shares Click's usage-error code) | One place to change if CI needs to tell them apart |
| 2026-11-25 | No Azure SDK or NetworkX deps in Phase A | Smaller surface until they are used (Phase B / M2) |
| 2026-11-25 | License Apache-2.0 (Daniel's decision) | Permissive with a patent grant |
| 2026-11-25 | PRs merged with merge commits (not squash); branch deleted after merge | Keeps the small conventional commits from each sub-step |
| 2026-11-25 | Contract targets normalized: every item is one target (`resource: <name or ARM ID>` or `directory: tenant`) plus `operations` | PLAN.md's `directory: [ops]` shorthand had a different shape from resource items (flag 13, approved) |
| 2026-11-25 | Short target names (`kv-crown-jewels`, `sp:billing-agent`) allowed; resolved against the snapshot in M2, ambiguous or unresolved = `inconclusive` | Names are not unique in Azure/Entra; full ARM IDs / objectIds also accepted |
| 2026-11-25 | Snapshot digest drops volatile fields declared per class (`collected_at`, `collector_version`, `provenance.observed_at`, `provenance.request_id`, `duration_ms`) | Spec excluded only `collected_at`; per-edge timestamps would have made "same digest twice" impossible |
| 2026-11-25 | Snapshot `mode` (LIVE/FIXTURE) is part of the digest | A fixture snapshot can never carry a live digest |
| 2026-11-25 | Canonical JSON = sorted keys, compact separators, UTF-8, no floats (floats rejected by models and canonicalizer) | Equivalent to RFC 8785 for our value types; needed for in-toto statements in M3 |
| 2026-11-25 | Entity IDs and ARM IDs normalized to lowercase; display names keep original case | ARM is case-insensitive and APIs return inconsistent casing for the same ID |
| 2026-11-25 | ARM ID parser and scope-operation grammar live in `fns.models` (pure, no I/O); the gate imports them | Models validate with them and must not depend on `fns.scope` |
| 2026-11-25 | Scope operations: `arm:<Namespace>/<type>/<read|write|delete|action>` and `graph:<METHOD> /<path>`, exact match, no wildcards. ARM `/action` and Graph non-GET are non-read | Unspecified in M1; `listKeys/action` reads secrets, so actions are never "read" |
| 2026-11-25 | Read-only verbs (scout, contain, prove, molt) reject non-read operations at manifest validation | Defence in depth; the gate re-checks independently (A3) |
| 2026-11-25 | `allowed_resource_groups` are full RG IDs whose subscription must be in `subscription_ids` | RG names are only unique within a subscription |
| 2026-11-25 | Scope expiry is checked by `load_scope(now=...)` and the gate, never in the model validator | Validation stays deterministic (no wall-clock reads); fixture replay can freeze the clock |
| 2026-11-25 | Strict YAML loader: duplicate keys, anchors/aliases, multi-doc and >1 MiB rejected; timestamps stay strings; only `true`/`false` are booleans | PyYAML keeps the last duplicate key silently (a second `tenant_id` would win); YAML 1.1 turns `no`/`on` into booleans |
| 2026-11-25 | All persisted models are frozen, `extra="forbid"`, with `version: 1` | Typos fail loudly; formats can evolve |
| 2026-11-25 | Snapshot edges: `hasRbacRole` dst = assignment scope; `hasDirectoryRole` dst = directoryRole entity (role definition GUID) with `directory_scope_id`; added `instanceOf` (SP -> app) and `hasIdentity` (resource -> MI) | Needed for PLAN's escalation primitives (app owner adds credential, MI on compute); avoids duplicating dst in an attribute |
| 2026-11-25 | Finding validation: pass on must_not_reach needs an observed denial and no observed/logged success; pass on must_still_do needs observed or logged success and no observed/logged denial; fail needs evidence pointing the failing way; coverage must equal the top rung with a result; gap labels need their disagreement | CLAUDE.md rule 4 enforced by the type system, not by convention |
| 2026-11-25 | Gate also checks the request URL: https, exact public-cloud host per API (`management.azure.com`, `graph.microsoft.com`), ARM path segment-wise under the target, Graph `/v1.0` or `/beta`; a page's nextLink may only change the query string | nextLink is untrusted API output (PLAN.md section 9); stops a call being redirected to another host or path |
| 2026-11-25 | Gate fails closed: any exception inside `check` is `INTERNAL_ERROR`; a journal write failure denies the call before the SDK callable runs | A bug or a lost audit trail must never become an allowed call |
| 2026-11-25 | Gate copies the manifest into an immutable policy at construction; malformed fields (forged via `model_construct`) mean deny-all | Later mutation of the manifest object cannot widen scope |
| 2026-11-25 | Subscription-scope reads are allowed when the subscription is listed, even if RGs are restricted; RG and resource targets need an allowed RG | scout must list role assignments at subscription scope (M1 B2); writes, when they exist, will be limited to resources inside allowed RGs |
| 2026-11-25 | `strike` requires the acting principal to be in `test_identities`; other verbs journal the principal only | Spec's `gate.check` had no acting identity; executor must only act as lab test identities |
| 2026-11-25 | Budget slot is reserved before the SDK callable runs and counted even if it raises | A crash or retry storm can never under-count API calls |
| 2026-11-25 | Fuzz suite asserts exact agreement between the gate and an independent oracle over generated parts; strategies weighted toward in-scope values | A planted string-prefix RG bug escaped uniform sampling (in-scope tuples were ~0.1% of examples); weighted strategies and a target-only property now catch it |
| 2026-11-25 | Ruff `BLE` enabled; broad `except` only at annotated fail-closed sites | In a security tool, swallowing exceptions elsewhere should be a lint error |
| 2026-11-25 | Tests that use the real clock build manifests that expire relative to now; committed examples are validated against a fixed date | No time bombs in CI when `scope.example.yaml` expires |
