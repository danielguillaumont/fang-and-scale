# M4 D2: logging and the detection rules, for sessions B to D. Off by default
# (enable_monitoring = false), so the M1 to M3 lab is unchanged and lab-down
# removes all of it with the rest.
#
# What feeds which table (tests/test_lab_monitoring.py checks every rule's table
# is fed):
#   subscription Activity Log  -> AzureActivity
#   Key Vault AuditEvent       -> AzureDiagnostics
#   blob StorageRead/Write     -> StorageBlobLogs
#   Entra AuditLogs            -> AuditLogs
#   Entra ServicePrincipalSignInLogs -> AADServicePrincipalSignInLogs
#     (both Entra categories export on Entra ID Free: docs/FINDINGS.md, 2026-11-27)
#
# The rules come from lab/detections.json, written by
# `fns detections export --terraform lab/detections.json` from detections/.
# A test fails when that file is out of date.

locals {
  monitoring_count = var.enable_monitoring ? 1 : 0

  detection_rules = {
    for id, rule in jsondecode(file("${path.module}/detections.json")).rules : id => rule
    if var.enable_monitoring
  }

  # The identities the strike plan monitors: sp-billing-agent and
  # app-escalation-target. Both object and client IDs are listed, because
  # AzureActivity's Caller for a service principal is not confirmed yet to be
  # one or the other (docs/DECISIONS.md, 2026-11-27).
  monitored_identities = jsonencode(sort([
    azuread_service_principal.billing_agent.object_id,
    azuread_service_principal.billing_agent.client_id,
    azuread_service_principal.escalation_target.object_id,
    azuread_service_principal.escalation_target.client_id,
  ]))

  blob_services = var.enable_monitoring ? {
    payroll  = "${azurerm_storage_account.payroll.id}/blobServices/default"
    invoices = "${azurerm_storage_account.invoices.id}/blobServices/default"
  } : {}
}

resource "azurerm_log_analytics_workspace" "lab" {
  count = local.monitoring_count

  name                = "law-${var.prefix}-${local.suffix}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = var.monitoring_daily_quota_gb
  tags                = local.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "lab" {
  count = local.monitoring_count

  workspace_id = azurerm_log_analytics_workspace.lab[0].id
}

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  count = local.monitoring_count

  name                       = "fns-${local.suffix}-activity"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab[0].id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
  }
}

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  count = local.monitoring_count

  name                           = "fns-${local.suffix}-kv"
  target_resource_id             = azurerm_key_vault.crown_jewels.id
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.lab[0].id
  log_analytics_destination_type = "AzureDiagnostics"

  enabled_log {
    category = "AuditEvent"
  }
}

resource "azurerm_monitor_diagnostic_setting" "blobs" {
  for_each = local.blob_services

  name                       = "fns-${local.suffix}-blob-${each.key}"
  target_resource_id         = each.value
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab[0].id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
}

# Tenant-level: it outlives the subscription's resources if Terraform's destroy
# fails halfway. The M4 runbook checks it is gone after lab-down.
resource "azurerm_monitor_aad_diagnostic_setting" "entra" {
  count = local.monitoring_count

  name                       = "fns-${local.suffix}-entra"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab[0].id

  enabled_log {
    category = "AuditLogs"
  }
  enabled_log {
    category = "ServicePrincipalSignInLogs"
  }
}

resource "azurerm_sentinel_alert_rule_scheduled" "rules" {
  for_each = local.detection_rules

  name                       = each.key
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab[0].workspace_id
  display_name               = each.value.display_name
  description                = each.value.description
  severity                   = each.value.severity
  query                      = replace(each.value.query, "{{monitored_identities}}", local.monitored_identities)
  query_frequency            = each.value.query_frequency
  query_period               = each.value.query_period
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT1H"
  tactics                    = each.value.tactics
  enabled                    = true

  dynamic "entity_mapping" {
    for_each = each.value.entity_mappings
    content {
      entity_type = entity_mapping.value.entity_type
      field_mapping {
        identifier  = entity_mapping.value.identifier
        column_name = entity_mapping.value.column_name
      }
    }
  }
}
