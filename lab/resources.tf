# Azure resources and RBAC for the lab. Synthetic data only.

resource "azurerm_key_vault" "crown_jewels" {
  name                       = "kv-crown-${local.suffix}"
  location                   = azurerm_resource_group.lab.location
  resource_group_name        = azurerm_resource_group.lab.name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  purge_protection_enabled   = false # lab-down must be able to purge it
  soft_delete_retention_days = 7
  tags                       = merge(local.tags, { "fns-role" = "crown-jewels" })
}

resource "azurerm_storage_account" "payroll" {
  name                            = "stpayroll${local.suffix}"
  location                        = azurerm_resource_group.lab.location
  resource_group_name             = azurerm_resource_group.lab.name
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  # Shared keys stay enabled on purpose: Contributor can call listKeys, one of the
  # blast-radius paths M2 must find.
  shared_access_key_enabled = true
  tags                      = merge(local.tags, { "fns-role" = "payroll" })
}

resource "azurerm_storage_account" "invoices" {
  name                            = "stinvoices${local.suffix}"
  location                        = azurerm_resource_group.lab.location
  resource_group_name             = azurerm_resource_group.lab.name
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = true
  tags                            = merge(local.tags, { "fns-role" = "invoices" })
}

# --- RBAC: the intended (and the unintended) access ---

resource "azurerm_role_assignment" "billing_agent_rg_contributor" {
  scope                = azurerm_resource_group.lab.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.billing_agent.object_id
  principal_type       = "ServicePrincipal"
  description          = "Fang & Scale lab: over-privileged on purpose."
}

resource "azurerm_role_assignment" "billing_agent_invoices" {
  scope                = azurerm_storage_account.invoices.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azuread_service_principal.billing_agent.object_id
  principal_type       = "ServicePrincipal"
  description          = "Fang & Scale lab: legitimate use (must_still_do)."
}

resource "azurerm_role_assignment" "verifier_rg_reader" {
  scope                = azurerm_resource_group.lab.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.verifier.object_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "scout_subscription_reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.scout.object_id
  principal_type       = "ServicePrincipal"
  description          = "Fang & Scale: read-only scout."
}

# Whoever runs lab-up needs data-plane rights to seed the synthetic data.
resource "azurerm_role_assignment" "runner_kv_secrets" {
  scope                = azurerm_key_vault.crown_jewels.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "runner_blobs" {
  for_each = {
    payroll  = azurerm_storage_account.payroll.id
    invoices = azurerm_storage_account.invoices.id
  }

  scope                = each.value
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

# New role assignments take a while to reach the data plane.
resource "time_sleep" "rbac_propagation" {
  create_duration = "90s"
  depends_on = [
    azurerm_role_assignment.runner_kv_secrets,
    azurerm_role_assignment.runner_blobs,
  ]
}

# --- synthetic data ---

resource "random_password" "synthetic_secret" {
  length  = 32
  special = false
}

resource "azurerm_key_vault_secret" "payroll_db" {
  name         = "payroll-db-password"
  value        = random_password.synthetic_secret.result
  key_vault_id = azurerm_key_vault.crown_jewels.id
  content_type = "synthetic; Fang & Scale lab"
  # fns prove reads this secret only if its ARM metadata carries this tag (M3 V6).
  tags       = merge(local.tags, { "fns-data" = "synthetic" })
  depends_on = [time_sleep.rbac_propagation]
}

resource "azurerm_storage_container" "payroll" {
  name                  = "payroll"
  storage_account_id    = azurerm_storage_account.payroll.id
  container_access_type = "private"
  depends_on            = [time_sleep.rbac_propagation]
}

resource "azurerm_storage_blob" "payroll" {
  name                 = "employees-SYNTHETIC.csv"
  storage_container_id = azurerm_storage_container.payroll.id
  type                 = "Block"
  content_type         = "text/csv"
  source_content       = "employee_id,name,salary\n1,Synthetic Person A,1\n2,Synthetic Person B,2\n"
}

resource "azurerm_storage_container" "invoices" {
  name                  = "invoices"
  storage_account_id    = azurerm_storage_account.invoices.id
  container_access_type = "private"
  depends_on            = [time_sleep.rbac_propagation]
}

resource "azurerm_storage_blob" "invoice" {
  name                 = "invoice-0001-SYNTHETIC.json"
  storage_container_id = azurerm_storage_container.invoices.id
  type                 = "Block"
  content_type         = "application/json"
  source_content       = jsonencode({ invoice = "0001", amount = 1, synthetic = true })
}
