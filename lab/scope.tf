# Renders ../scope.lab.yaml (gitignored) for `fns scout` and `fns prove --live`. The expiry is fixed when
# the lab is created (time_offset), so plans stay stable; re-render it with:
#   terraform -chdir=lab apply "-replace=time_offset.scope_expiry"   (quoted for PowerShell)

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

locals {
  # What `fns prove --live` may read as sp-billing-agent (M3 P5; docs/milestones/
  # M3-live-plan.md). Reads only: the gate has no write form for kv: or blob:.
  # tests/test_lab.py checks these against the probe code.
  secret_op       = "kv:GET /secrets/${azurerm_key_vault_secret.payroll_db.name}"
  payroll_blob_op = "blob:HEAD /${azurerm_storage_container.payroll.name}/${azurerm_storage_blob.payroll.name}"
  invoice_blob_op = "blob:HEAD /${azurerm_storage_container.invoices.name}/${azurerm_storage_blob.invoice.name}"
  prove_operations = [
    "arm:Microsoft.Authorization/permissions/read",
    "arm:Microsoft.KeyVault/vaults/secrets/read",
    "kv:GET /secrets",
    local.secret_op,
    local.payroll_blob_op,
    local.invoice_blob_op,
  ]
  data_objects = [
    { resource = azurerm_key_vault.crown_jewels.id, operation = local.secret_op },
    { resource = azurerm_storage_account.payroll.id, operation = local.payroll_blob_op },
    { resource = azurerm_storage_account.invoices.id, operation = local.invoice_blob_op },
  ]
}

resource "local_file" "scope" {
  filename        = "${path.module}/../scope.lab.yaml"
  file_permission = "0600"
  content = templatefile("${path.module}/scope.lab.yaml.tftpl", {
    tenant_id        = lower(var.tenant_id)
    subscription_id  = lower(var.subscription_id)
    resource_group   = azurerm_resource_group.lab.id
    agent_object_id  = azuread_service_principal.billing_agent.object_id
    agent_app_id     = azuread_application.billing_agent.client_id
    operations       = local.scout_operations
    prove_operations = local.prove_operations
    data_objects     = local.data_objects
    expires_at       = time_offset.scope_expiry.rfc3339
  })
}
