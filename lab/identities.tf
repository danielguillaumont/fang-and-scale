# Workload identities for the lab (PLAN.md section 7). No credentials are created
# here: sp-billing-agent and app-escalation-target never need to sign in for M1,
# and the scout identity signs in through the Azure CLI (README, "Live scout").

data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph, same in every tenant
}

locals {
  graph_roles = data.azuread_service_principal.msgraph.app_role_ids
  owners      = [data.azuread_client_config.current.object_id]
}

# --- sp-billing-agent: the identity assumed compromised (over-privileged on purpose) ---

resource "azuread_application" "billing_agent" {
  display_name = "sp-billing-agent"
  owners       = local.owners
  tags         = local.ad_tags
  notes        = "Fang & Scale lab: assumed-compromised workload identity. Over-privileged on purpose."
}

resource "azuread_service_principal" "billing_agent" {
  client_id = azuread_application.billing_agent.client_id
  owners    = local.owners
  tags      = local.ad_tags
}

resource "azuread_app_role_assignment" "billing_agent_owned_by" {
  app_role_id         = local.graph_roles["Application.ReadWrite.OwnedBy"]
  principal_object_id = azuread_service_principal.billing_agent.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# --- app-escalation-target: owned by the agent, holds a privileged Graph permission ---
# The escalation path the lab exists to expose: billing-agent owns this app, so it
# can add a credential to it and act with AppRoleAssignment.ReadWrite.All.

# S4's marker role (enable_strikes only, approved 2026-11-27): an app role that grants
# nothing, defined here and never by a strike. S4 assigns it to the agent as this
# app's identity, which proves AppRoleAssignment.ReadWrite.All, then removes it.
resource "random_uuid" "strike_marker" {
  count = var.enable_strikes ? 1 : 0
}

resource "azuread_application" "escalation_target" {
  display_name = "app-escalation-target"
  owners       = concat(local.owners, [azuread_service_principal.billing_agent.object_id])
  tags         = local.ad_tags
  notes        = "Fang & Scale lab: privileged app owned by sp-billing-agent (escalation target)."

  dynamic "app_role" {
    for_each = random_uuid.strike_marker
    content {
      id                   = app_role.value.result
      value                = "fns.strike.marker"
      display_name         = "Fang & Scale strike marker"
      description          = "Grants nothing"
      allowed_member_types = ["Application"]
      enabled              = true
    }
  }
}

resource "azuread_service_principal" "escalation_target" {
  client_id = azuread_application.escalation_target.client_id
  owners    = local.owners
  tags      = local.ad_tags
}

resource "azuread_app_role_assignment" "escalation_target_privileged" {
  app_role_id         = local.graph_roles["AppRoleAssignment.ReadWrite.All"]
  principal_object_id = azuread_service_principal.escalation_target.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# --- id-verifier: read-only identity used only by `fns prove` (M3) ---

resource "azuread_application" "verifier" {
  display_name = "id-verifier"
  owners       = local.owners
  tags         = local.ad_tags
  notes        = "Fang & Scale lab: read-only verifier identity (fns prove)."
}

resource "azuread_service_principal" "verifier" {
  client_id = azuread_application.verifier.client_id
  owners    = local.owners
  tags      = local.ad_tags
}

# --- sp-fns-scout: the read-only identity `fns scout` runs as ---
# Exactly the permissions documented in README.md ("Scout permissions").

resource "azuread_application" "scout" {
  display_name = "sp-fns-scout"
  owners       = local.owners
  tags         = local.ad_tags
  notes        = "Fang & Scale: read-only scout. Reader on the lab subscription + Graph read permissions."
}

resource "azuread_service_principal" "scout" {
  client_id = azuread_application.scout.client_id
  owners    = local.owners
  tags      = local.ad_tags
}

resource "azuread_app_role_assignment" "scout_graph" {
  for_each = toset(concat(
    ["Application.Read.All", "LicenseAssignment.Read.All", "RoleManagement.Read.Directory"],
    var.scout_directory_read_all ? ["Directory.Read.All"] : [],
  ))

  app_role_id         = local.graph_roles[each.key]
  principal_object_id = azuread_service_principal.scout.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

resource "azuread_application_federated_identity_credential" "scout_github" {
  count = var.github_repository == "" ? 0 : 1

  application_id = azuread_application.scout.id
  display_name   = "github-main"
  description    = "GitHub Actions OIDC, main branch only. No client secret exists."
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_repository}:ref:refs/heads/main"
}
