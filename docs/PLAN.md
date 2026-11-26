# Fang & Scale: Product & Build Plan (Entra/Azure-first)

As of 2026-11-25. The canonical, commentable copy lives in Daniel's Claude doc;
this file is the repo copy that Claude Code reads.

## 1. Thesis

Fang & Scale is unit tests for breach blast radius in Microsoft Entra and Azure.
You declare what a compromised workload or AI agent identity must never reach and
what it must still be able to do. The tool attacks the boundary, proposes the
smallest fix, proves it with signed evidence, and fails your pull request if it
ever regresses.

- Hook: *Assume your agent gets prompt-injected. Prove what it can't touch.*
- Promise: Challenge the defence. Reduce the damage. Prove the improvement.

## 2. Scope

v0.1 proves one loop end to end: a compromised workload identity in one Entra
tenant and one Azure subscription.

In scope for v0.1:
- Identities: service principals, managed identities; Entra Agent ID agent
  identities in milestone 6.
- Permission surfaces: Azure RBAC role assignments (management group to resource),
  deny assignments, Microsoft Graph application permissions (appRoleAssignments),
  app and service principal ownership, directory role assignments.
- Escalation primitives modelled: app owner adds a credential;
  `AppRoleAssignment.ReadWrite.All` self-grant;
  `Microsoft.Authorization/roleAssignments/write`; storage `listKeys`;
  Key Vault data access; VM Run Command; Automation runbooks.
- Control plane vs data plane: Contributor + `listKeys` effectively reads data.
  Model that edge explicitly.
- Outputs: CLI, JSON evidence bundle, static HTML report, GitHub Action PR comment.

Not in v0.1: other clouds, cross-tenant, on-prem AD, user-identity attacks
(phishing, spray, MFA fatigue), any write outside the declared lab, autonomous
remediation outside the lab, web console, hosted service, LLM features beyond a
disabled-by-default proposal adapter.

## 3. Product surface

CLI `fns`. The user writes two kinds of file: `scope.yaml` and `contracts/*.fns.yaml`.

| Command | Module | What it does | Writes? |
| --- | --- | --- | --- |
| `fns scout` | Inventory | Read-only snapshot of RBAC, Graph perms, owners, directory roles; optional AzureHound/ROADrecon import | No |
| `fns contain` | Antivenom | Assumed-compromise reach, contract evaluation, coverage states, mutation testing | No |
| `fns strike` | Fang | Approved scenarios (Stratus Red Team Entra/Azure + own probes) as test identities | Lab only, approved |
| `fns harden` | Scale | Smallest Terraform diff satisfying the contract; applies to lab after approval | Lab only, approved |
| `fns prove` | Verifier | Re-runs assertions with separate read-only credentials; signed bundle | No |
| `fns molt` | Drift | Diffs two snapshots; invalidates conclusions whose facts changed | No |

### scope.yaml
Tenant ID, subscription IDs, allowed resource groups, test identities, allowed
operations per verb, budget (API calls, minutes), expiry date. Missing or expired
field means deny.

### Contract example
```yaml
contract: billing-agent-blast-radius
assume_compromised: sp:billing-agent
must_not_reach:
  - resource: kv-crown-jewels
    operations: [secrets/get, secrets/list]
  - directory: [roleAssignments/write, applications/credentials/update]
  - resource: st-payroll
    operations: [listKeys, blob/read]
must_still_do:
  - resource: st-invoices
    operations: [blob/read, blob/write]
    source: recorded
budget:
  max_critical_reachable: 0
  max_inconclusive: 2
on_inconclusive: fail
```
Results: `pass`, `fail`, `inconclusive`, each with its evidence rung.

## 4. Evidence ladder

| Rung | Source | Proves | Limits |
| --- | --- | --- | --- |
| 1 Modeled | Own graph from ARM + Graph (+ optional AzureHound) | What config implies | Misses conditions, PIM eligibility, service-specific auth |
| 2 Evaluated | ARM `Microsoft.Authorization/permissions` called as the test identity; Graph CA What-If `/identity/conditionalAccess/evaluate` | What the platform says it would allow | Control plane only; What-If needs all sign-in conditions |
| 3 Observed | Live non-destructive probe with test identity token against lab fixtures | What actually succeeded/was denied | Only operations in scope |
| 4 Logged/Detected | Activity Log, Entra audit/sign-in logs in Log Analytics; Sentinel rule fired | Defenders could see it; alert fired in time | Latency; sign-in logs need P1 |

Rules:
- A `pass` on a `must_not_reach` item needs rung 3 (observed denial).
- Rung 1 reachable but rung 3 denied: finding `model-gap`.
- Rung 2 denied but rung 3 allowed: finding `platform-gap` (highest severity).
- Strike observed at rung 3 with no rung 4 alert: finding `detection-gap`.

## 5. Signature features

1. Blast Radius as Code: versioned YAML contracts, CI exit codes.
2. Record mode: run the workload's functional test as its identity, harvest
   performed operations from logs, write `must_still_do` with `source: recorded`.
3. Defense mutation testing: mutate hardened Terraform (add Owner at RG, add
   `listKeys`, add Graph app permission, add app owner, remove deny assignment).
   Each mutant must make a contract fail. Mutation score = killed / total.
4. Signed proof bundles: assertions frozen + hashed before run; verifier in a
   separate process with separate read-only identity; Sigstore keyless signing,
   in-toto statement shape.
5. Coverage states: `verified`, `evaluated-only`, `modeled-only`, `not-assessed`,
   `out-of-scope`. Reports lead with coverage, not a risk score.

Supporting: hypothesis ledger for strikes; `molt` drift invalidation; PR comment
like `Blast radius: +2 critical reachable · mutation 14/15 · bundle signed`.

## 6. Architecture

One Python package, journaled run state machine, hard trust boundary.
- Proposer (`harden`, optional LLM): diffs and hypotheses only, no write creds.
- Executor (`strike`, lab apply): short-lived lab-only creds, every call via scope gate.
- Verifier (`prove`): own process, own read-only identity, reads only frozen
  assertions + evidence journal. Package `fns.verify` imports nothing from executor.
- Run journal: append-only SQLite; idempotent keyed steps; resume never repeats a
  write or counts a crash as pass.

Stack: Python 3.12, Typer + Rich, Pydantic v2 (JSON Schema export), azure-identity,
azure-mgmt-authorization, azure-mgmt-resource, msgraph-sdk, NetworkX, SQLite +
content-addressed artifact folder, Terraform azurerm + azuread, Log Analytics +
Sentinel (KQL as code), sigstore-python, GitHub Actions with OIDC, static HTML +
Cytoscape.js report, later MCP server + Claude Code skill, pytest + hypothesis.

## 7. Lab

Dedicated tenant from an Azure free account. Entra ID P2 trial only at M4.
Sentinel 31-day free trial (10 GB/day) only at M4.

Terraform `lab/` builds:
- `sp-billing-agent`: identity assumed compromised; over-privileged on purpose
  (Contributor on RG, `Application.ReadWrite.OwnedBy`, owner of a second app).
- `kv-crown-jewels` with synthetic secret; `st-payroll` with synthetic blobs.
- `st-invoices`: what the agent legitimately uses.
- `app-escalation-target`: second app reg with a privileged Graph permission.
- `id-verifier`: read-only identity used only by `prove`.
- Log Analytics workspace with Activity Log + Entra diagnostic settings (M4).

Fixture mode: every live run is recorded; `fns demo` replays without a tenant and
labels every result `FIXTURE`.

## 8. Milestones

| # | Name | Exit gate |
| --- | --- | --- |
| M1 | Lab + contracts | `terraform apply` builds lab; `fns scout` snapshot digest identical twice; scope + contract JSON Schema published |
| M2 | Contain (Antivenom) | `fns contain` fails seeded contract, prints escalation path with rung labels + coverage |
| M3 | Prove | Live probes confirm/refute each path; `fns prove` under `id-verifier`; bundle verifies with Sigstore |
| M4 | Harden + detect | Record mode writes `must_still_do`; `fns harden` turns contract green with legit use kept; each strike has a KQL rule + detection result |
| M5 | Mutation + CI | Mutation score per contract; GitHub Action PR comments; `fns demo` with no tenant; README/report/brand; v0.1 tagged |
| M6 | Strike + agents | Stratus Entra/Azure adapters; Agent ID; MCP server + Claude Code skill; LLM vs deterministic bake-off |

## 9. Safety

Scope gate in code; executor RBAC limited to lab RG; tenant pinning; non-destructive
strikes with journaled cleanup; `--approve <plan-hash>` for writes; secretless CI;
Graph/ARM metadata and logs treated as untrusted (prompt injection); never external
targets, credential harvesting, production tenants or retaliation.

## 10. Metrics

Reach accuracy (modeled vs observed, every disagreement explained); mutation score;
legitimate use preserved (all pass or change rejected); detection coverage; scope
safety (100% of fuzzed out-of-scope calls blocked); reproducibility (identical
verdicts and digests excluding timestamps); resume safety; LLM vs deterministic
bake-off (M6). No composite score; publish exact denominators.

## 11. Brand

Product Fang & Scale; repo `fang-and-scale`; CLI `fns`; modules Fang, Antivenom,
Scale, Molt. Lines: "Challenge the defence. Reduce the damage. Prove the
improvement." / "Prove what the bite can't reach." Palette: Obsidian #0E1116,
Bone #ECE8DF, Venom #B8F03A (single accent, pass/highlight only), Scale Copper
#B87333, Slate #5B6573; fail uses standard red. Rich CLI theme uses these.
