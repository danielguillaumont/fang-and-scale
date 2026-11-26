locals {
  tags = {
    project = "fang-and-scale"
    purpose = "lab"
  }
  # azuread objects take string tags.
  ad_tags = ["project=fang-and-scale", "purpose=lab"]
  suffix  = random_string.suffix.result
}

data "azurerm_client_config" "current" {}
data "azuread_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.prefix}-lab"
  location = var.location
  tags     = local.tags

  lifecycle {
    precondition {
      condition     = lower(data.azurerm_client_config.current.tenant_id) == lower(var.tenant_id)
      error_message = "Signed-in tenant does not match var.tenant_id. Refusing to touch another tenant."
    }
    precondition {
      condition     = lower(data.azuread_client_config.current.tenant_id) == lower(var.tenant_id)
      error_message = "azuread is signed in to a different tenant than var.tenant_id."
    }
  }
}
