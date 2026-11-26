output "tenant_id" {
  value = var.tenant_id
}

output "subscription_id" {
  value = var.subscription_id
}

output "resource_group_id" {
  value = azurerm_resource_group.lab.id
}

output "scope_file" {
  description = "Scope manifest for `fns scout`."
  value       = abspath(local_file.scope.filename)
}

output "scope_expires_at" {
  value = time_offset.scope_expiry.rfc3339
}

output "scout" {
  description = "Read-only identity fns scout signs in as."
  value = {
    client_id = azuread_application.scout.client_id
    object_id = azuread_service_principal.scout.object_id
  }
}

output "identities" {
  description = "Object IDs of the lab service principals."
  value = {
    billing_agent     = azuread_service_principal.billing_agent.object_id
    escalation_target = azuread_service_principal.escalation_target.object_id
    verifier          = azuread_service_principal.verifier.object_id
  }
}

output "resources" {
  value = {
    key_vault        = azurerm_key_vault.crown_jewels.id
    storage_payroll  = azurerm_storage_account.payroll.id
    storage_invoices = azurerm_storage_account.invoices.id
  }
}

output "billing_agent" {
  description = "The test identity fns prove --live signs in as (M3 runbook)."
  value = {
    client_id = azuread_application.billing_agent.client_id
    object_id = azuread_service_principal.billing_agent.object_id
  }
}
