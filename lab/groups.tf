# M4 D3: one lab group, so /servicePrincipals/{id}/memberOf has something to
# return. Session A's "can the scout drop Directory.Read.All?" test compares what
# the scout sees with and without that permission; with no group in the lab,
# memberOf returned nothing either way.
#
# The group holds no roles: no Azure RBAC assignment, no directory role, no app
# role (tests/test_lab_group.py). It changes what the scout sees, not what the
# agent can reach.

resource "azuread_group" "billing" {
  display_name     = "grp-${var.prefix}-billing"
  description      = "Fang & Scale lab group (project=fang-and-scale, purpose=lab). sp-billing-agent is its only member. No roles."
  security_enabled = true
  mail_enabled     = false
  owners           = local.owners
  members          = [azuread_service_principal.billing_agent.object_id]

  # A group that can take directory roles needs a privileged role to create, and
  # is not what D3 asked for.
  assignable_to_role = false
}
