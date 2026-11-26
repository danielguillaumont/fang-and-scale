# Renders ../scope.lab.yaml (gitignored) for `fns scout`. The expiry is fixed when
# the lab is created (time_offset), so plans stay stable; re-render it with:
#   terraform -chdir=lab apply -replace=time_offset.scope_expiry

resource "time_offset" "scope_expiry" {
  offset_days = var.scope_valid_days
}

locals {
  # Must match the collector's request catalogue (fns.adapters.azure.arm/graph);
  # tests/test_lab.py fails if they drift.
  scout_operations = [
    "arm:Microsoft.Authorization/roleAssignments/read",
    "arm:Microsoft.Authorization/roleDefinitions/read",
    "arm:Microsoft.Authorization/denyAssignments/read",
    "arm:Microsoft.Resources/subscriptions/resourceGroups/resources/read",
    "arm:Microsoft.KeyVault/vaults/read",
    "arm:Microsoft.Storage/storageAccounts/read",
    "arm:Microsoft.Authorization/roleEligibilitySchedules/read",
    "graph:GET /servicePrincipals",
    "graph:GET /applications",
    "graph:GET /servicePrincipals/{id}/owners",
    "graph:GET /applications/{id}/owners",
    "graph:GET /servicePrincipals/{id}/appRoleAssignments",
    "graph:GET /servicePrincipals/{id}/memberOf",
    "graph:GET /roleManagement/directory/roleDefinitions",
    "graph:GET /roleManagement/directory/roleAssignments",
    "graph:GET /roleManagement/directory/roleEligibilitySchedules",
    "graph:GET /subscribedSkus",
  ]
}

resource "local_file" "scope" {
  filename        = "${path.module}/../scope.lab.yaml"
  file_permission = "0600"
  content = templatefile("${path.module}/scope.lab.yaml.tftpl", {
    tenant_id       = lower(var.tenant_id)
    subscription_id = lower(var.subscription_id)
    resource_group  = azurerm_resource_group.lab.id
    agent_object_id = azuread_service_principal.billing_agent.object_id
    operations      = local.scout_operations
    expires_at      = time_offset.scope_expiry.rfc3339
  })
}
