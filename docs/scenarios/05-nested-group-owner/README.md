# 5. A nested group makes the agent Owner (FIXTURE)

**Story.** `sp-sync-agent` is in `grp-sync-workers`, an ordinary group. Long
ago, `grp-sync-workers` was added to `grp-platform-admins`, which holds
**Owner** on the resource group. The agent's direct memberships show nothing
privileged; the nested one makes it Owner of everything in `rg-app`.

The tenant's scope lists the new transitive-membership read, so the scout
sees the nested group.

**Contract** (`tenant/contract.fns.yaml`):

```yaml
assume_compromised: sp:sp-sync-agent
must_not_reach:
  - resource: kv-crown
    operations: [secrets/get, roleAssignments/write]
```

**Run:** `uv run fns demo contain --fixture docs/scenarios/05-nested-group-owner/tenant`

**Expected** ([full output](expected-tenant.txt)): `FAIL resource:kv-crown
roleAssignments/write` (Owner includes it) and `secrets/get` (Owner can grant
itself any role), exit 1. The path's membership hop comes from
`transitiveMemberOf`:

```text
2. [member-of] sp-sync-agent is in the group grp-platform-admins; its grants apply
     from memberOf: sp-sync-agent -> grp-platform-admins [graph:GET /servicePrincipals/{id}/transitiveMemberOf/microsoft.graph.group]
```

**Fix:** take `grp-sync-workers` out of `grp-platform-admins`. After the fix
([output](expected-fixed.txt)) both findings are `inconclusive` (not reached),
within budget, exit 0.

**Why the rule holds.** "Role assignments are transitive for groups, which
means that if a user is a member of a group and that group is a member of
another group that has a role assignment, the user has the permissions in the
role assignment"
([Azure RBAC overview](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview));
the service principal listing "will include all groups that this service
principal is a nested member of"
([List transitiveMemberOf](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-transitivememberof?view=graph-rest-1.0)).
The overview's sentence names a user; that it applies the same way to a
service principal member is the model's reading, not yet validated live
(LV-9).
