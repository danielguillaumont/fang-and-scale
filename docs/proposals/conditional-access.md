# Proposal: reading Conditional Access for workload identities

**Status: design only, pending review (2026-11-28).** Nothing here is built.
It needs a Graph permission the scout does not have (`Policy.Read.All`), and
the session that wrote it had a hard rule against new permissions. The surface
`conditional-access` stays **not collected** in every snapshot until Daniel
decides.

All platform statements below are from Microsoft Learn, read 2026-11-28, and
are **not yet validated live** (backlog rows LV-11 to LV-13).

## The gap today

Every snapshot lists `conditional-access: not collected in M1`. The reach model
assumes a compromised workload identity can use whatever it holds. A
Conditional Access policy that blocks the service principal (for example
outside named locations) could make some of that reach unusable from where
the attacker sits. The model can't tell, so it says nothing either way.

The surface is not one of the semantics surfaces (`OperationSemantics.surfaces`
or `GLOBAL_SURFACES`), so it never makes a finding inconclusive today. This
proposal keeps it that way (see "What it would not change").

## What the platform offers

From [Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity):

- **Licence.** "Workload Identities Premium licenses are required to create or
  modify Conditional Access policies scoped to service principals." Reading
  existing policies is a separate question (below), and so is whether a policy
  made while a licence was active still applies after it lapses (not stated;
  LV-13).
- **Who is covered.** "Policy can be applied to single tenant service
  principals that are registered in your tenant. Microsoft and third-party
  SaaS applications, including multitenant apps, are not covered by these
  policies. Managed identities aren't covered by policy."
- **Conditions.** Location, and service principal risk ("Based on risk
  detected by Microsoft Entra ID Protection").
- **Controls.** "Under **Grant**, **Block access** is the only available
  option."
- **Groups.** "Conditional Access policies assigned to a group that contains a
  service principal are not enforced for that service principal."

From [List policies](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0):
the least-privileged application permission is **`Policy.Read.All`**; the
page lists no higher-privileged alternative for applications ("Not available").

## What would be needed

1. **Permission:** `Policy.Read.All` (application) on the scout, granted by a
   tenant admin. As its name says, it is a tenant-wide policy read, not one
   limited to Conditional Access (what else it exposes is LV-12), so it widens
   what a stolen scout credential discloses. This is the main cost, and it's
   why the change is Daniel's to make.
2. **Scope operation:** `graph:GET /identity/conditionalAccess/policies`, an
   optional read like the PIM and credential reads: the collector runs only
   when a scope lists it, so existing scopes, recordings and digests don't
   change.
3. **Collector `graph.conditional-access`:** keep, per policy, the state
   (`enabled`, `disabled`, `enabledForReportingButNotEnforced`), the
   `conditions.clientApplications` include/exclude service principal lists
   (and any service principal filter), locations, service principal risk
   levels, and the grant controls. Don't keep display names of named locations
   or IP ranges beyond what the model needs. The recorder already sanitizes
   GUIDs; IP ranges would need a new sanitizer rule before any recording is
   committed.
4. **Licence evidence:** `/subscribedSkus` is already read for PIM. A tenant
   with no Workload Identities Premium plan can't create or modify policies
   scoped to service principals, so the surface could become `not-applicable`
   with that evidence, under the same rule as PIM: by service plan ID only, never by
   name, and from an explicit list that starts empty. Learn says the licence
   is needed to *create or modify* such policies; whether a policy created
   while a licence was active keeps applying after it lapses is not stated
   (LV-13), so a lapsed licence would not count as evidence.

## What it would change

- **Report context, not reach.** A policy that applies to the compromised
  service principal would be listed with its finding (like front doors are
  today): "sign-ins as sp-agent are blocked outside named locations X". It
  would be a reason on the finding, at rung 1 (modeled).
- **Coverage honesty.** `conditional-access` would leave `not collected` when
  the read succeeds, or become `not-applicable` with licence evidence.

## What it would not change

- **No verdict ever turns to `pass` because of a policy.** A block policy is a
  condition on *where* the attacker signs in, not on what the identity can
  reach. An attacker inside an allowed location, or one who already holds a
  token, still reaches everything. Treating CA as a
  reach reduction would claim more than the evidence (CLAUDE.md rule 4).
- **Managed identities and multi-tenant apps:** not covered by CA at all
  (quoted above), so nothing changes for them; the report would say so
  rather than show "no policy".
- **Group-assigned policies:** not enforced for service principals (quoted
  above); the collector would read them only to say they don't apply.
- **Report-only policies** (`enabledForReportingButNotEnforced`) block nothing;
  they would be listed as such.

## Optional later step: What-If

PLAN.md's rung 2 mentions the CA What-If API
(`/identity/conditionalAccess/evaluate`). It needs every sign-in condition
(location, risk), which the tool doesn't know for an attacker, so it can say
at most "blocked from here". Out of scope for this proposal.

## Decision needed

| Option | What it costs | What it gives |
| --- | --- | --- |
| **A. Keep not collected (today, conservative)** | Nothing | The report keeps saying CA is not collected |
| B. Grant `Policy.Read.All`, collect as above | A broader read permission on the scout; a new collector, sanitizer rule and tests | CA context on findings, `not-applicable` on tenants without the licence |
| C. Licence-only: use `/subscribedSkus` (already read) to mark `not-applicable` when no plan can carry workload-identity CA | Needs a vetted list of plan IDs, like `PIM_FREE_PLAN_IDS` (starts empty) | Honest `not-applicable` on Free tenants like the lab, no new permission |

Recommendation: **C first** (no new permission, same evidence rule as PIM),
B only if a real tenant needs the context. Until Daniel decides, A is what the
code does.
