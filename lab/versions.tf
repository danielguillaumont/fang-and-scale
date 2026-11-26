terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.15"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.14"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.9"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }
}

# State is local (lab/terraform.tfstate, gitignored). It holds the synthetic
# Key Vault secret and object IDs of the lab tenant: never commit it.

provider "azurerm" {
  subscription_id     = var.subscription_id
  tenant_id           = var.tenant_id
  storage_use_azuread = true

  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "azuread" {
  tenant_id = var.tenant_id
}
