# M6 design notes: Entra Agent ID

**Status: design notes only.** Nothing here is built. The Microsoft behaviour
below comes from Microsoft's documentation, read on 2026-11-27, not from a lab
run. Every "to verify" item has to be observed in the lab before code depends
on it, and recorded in `docs/FINDINGS.md` where it differs from the docs.

PLAN section 2 puts Entra Agent ID agent identities in scope for M6. The
question for Fang & Scale is the same as for any workload identity: if this
agent identity is compromised, what can it reach, and is that what the
contract allows?

## What Microsoft documents

Sources:
- [Agent identities, service principals, and applications](https://learn.microsoft.com/en-us/entra/agent-id/agent-service-principals)
- [Create an agent identity blueprint](https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint)
- [Create agent identities](https://learn.microsoft.com/en-us/entra/agent-id/create-delete-agent-identities)
- [agentIdentity resource type (Graph v1.0)](https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-1.0)
- [agentIdentityBlueprintPrincipal resource type (Graph v1.0)](https://learn.microsoft.com/en-us/graph/api/resources/agentidentityblueprintprincipal?view=graph-rest-1.0)

There are three objects:

| Object | Graph shape | Role |
| --- | --- | --- |
| **Agent identity blueprint** | an application, `@odata.type` `#microsoft.graph.agentIdentityBlueprint` | The template. It holds the credentials. |
| **Blueprint principal** | a service principal, `#microsoft.graph.agentIdentityBlueprintPrincipal`, one per tenant the blueprint runs in | Gets app-only tokens for the blueprint in that tenant |
| **Agent identity** | a service principal, `#microsoft.graph.agentIdentity`, with `agentIdentityBlueprintId` and a sponsor | The identity an agent runs as |

The documentation also says:
- an agent identity can list the **app role assignments it inherits** from its
  blueprint principal;
- agent identities are created with a POST to
  `servicePrincipals/microsoft.graph.agentIdentity`, giving a display name, the
  blueprint ID and a sponsor;
- creating blueprints needs `AgentIdentityBlueprint.Create` and
  `AgentIdentityBlueprintPrincipal.Create`;
- reading blueprint principals needs `AgentIdentityBlueprintPrincipal.Read.All`.

**The docs disagree with themselves in one place.** The migration guide sets up
credentials with a POST of only an `appId` to the generic `servicePrincipals`
endpoint. The creation guide uses the dedicated blueprint-principal type. To
verify (V-A1).

## Why it changes the blast radius

1. **Inherited permissions.** An agent identity's reach is its own grants
   *plus* what it inherits from its blueprint principal. A model that reads
   only the agent identity's own `appRoleAssignments` under-reports its reach.
2. **One blueprint, many agents.** The blueprint holds the credentials. If it
   can get tokens as each of its agent identities, then compromising the
   blueprint means compromising every agent made from it. Hypothesis, to verify
   (V-A3): the blueprint's blast radius is the union of its agents' blast radii.
3. **Sponsors and owners** are new edges. Whether a sponsor can add credentials
   or change permissions is not established here. To verify (V-A4).

## The gap today

`fns.adapters.azure.graph` reads `/servicePrincipals` and types each one as
`servicePrincipal` or `managedIdentity`, from `servicePrincipalType`. **An agent
identity would be collected as a plain service principal, and its inherited
permissions would be invisible to the model.**

This does not produce a false `pass`: a `must_not_reach` pass needs an observed
denial (rung 3). It can, however, make a modeled reach look smaller than it is,
and a reviewer reading a modeled-only result would be misled.

**Proposed first step, before any other Agent ID code (pending review):**
- the collector recognises the three `@odata.type` values;
- until inheritance is modeled, every finding whose compromised principal is an
  agent identity, a blueprint or a blueprint principal gets coverage
  `not-assessed`, with the reason "Agent ID inheritance not modeled".

This only makes results stricter (toward `inconclusive`). Under the D6 guardrail
("may only gain evidence or become stricter"), it still needs approval, because
it changes coverage on findings that exist today.

## Design, once the facts are verified

- **Snapshot.** New entity types `agentIdentity`, `agentBlueprint` and
  `agentBlueprintPrincipal`, plus two edges:
  - `inheritsFrom` (agent identity → blueprint principal);
  - `canActAs` (blueprint → each agent identity), only once V-A3 is observed.

  This is a new semantics version, so contain reports say which semantics they
  used, as they do now.
- **Closure.** The principal closure follows `inheritsFrom` for app role
  assignments, and `canActAs` as an escalation primitive, labelled like the
  existing ones.
- **Contracts.** No schema change for an agent identity as `compromised`: it is
  a service principal ID. Naming a *blueprint* as `compromised` needs schema v3,
  as its own decision.
- **Scope.** Read-only verbs only. The scout needs
  `AgentIdentityBlueprintPrincipal.Read.All` (and whatever V-A2 shows is needed
  to read agent identities). There is no write path: creating agent identities
  in the lab is Terraform's job (or a runbook step), never the tool's.
- **Probes (rung 3).** To prove a denial as the agent identity, `prove --live`
  needs a token *as* that agent identity. How the blueprint's credential is
  exchanged for it is to verify (V-A5). Until then, Agent ID findings stop at
  rung 2 and stay `inconclusive`, never `pass`.
- **Strikes.** None in M6 for Agent ID. A strike that acts as an agent through
  its blueprint would need its own plan, its own write forms and its own
  approval.

## To verify in the lab (each one goes into FINDINGS.md)

| # | Question | How |
| --- | --- | --- |
| V-A1 | Which endpoint creates the blueprint principal, and what does it return? | Create one by hand in the lab; record both requests from the docs |
| V-A2 | How do agent identities appear in `GET /servicePrincipals`? `@odata.type`, `servicePrincipalType`, and whether `$select` hides them | Scout an agent and diff the responses |
| V-A3 | Can the blueprint's credential get a token as each agent identity in the tenant? | Probe as the blueprint; record the token's `oid` claim without storing the token |
| V-A4 | What can a sponsor do to an agent identity (credentials, permissions)? | A read-only permissions probe as a sponsor test user |
| V-A5 | The token exchange that `prove` would need to act as the agent | Follow the documented flow in the lab |
| V-A6 | Licensing, preview status and cost in the lab tenant | The admin center, before building anything |

## Lab

- **Terraform support.** The `azuread` provider may not support these objects
  yet. If not, a runbook step creates them by hand, and `lab/` records their IDs
  as variables. Check this before session planning.
- **What to build.** A single blueprint with two agent identities: one granted
  `Application.ReadWrite.OwnedBy` directly, and one that inherits an app role
  from the blueprint principal. That gives the contract one finding per edge.

## Decisions this needs

Each is pending review. None is built.

1. The "not-assessed until modeled" coverage rule above.
2. Whether Agent ID needs a P1/P2 or preview licence in the lab, and its cost
   (Needs Daniel, with V-A6).
3. Schema v3 for a blueprint as `compromised`.
