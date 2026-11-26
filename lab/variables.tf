variable "tenant_id" {
  description = "Dedicated lab tenant (never a production tenant)."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

variable "subscription_id" {
  description = "Lab subscription inside the lab tenant."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
  }
}

variable "location" {
  description = "Azure region for lab resources. Required: subscription policy may restrict regions (docs/runbooks/m1-live-run.md, step 3)."
  type        = string
}

variable "scout_directory_read_all" {
  description = "Grant Directory.Read.All to sp-fns-scout. Set false to test whether the scout works without it (docs/FINDINGS.md)."
  type        = bool
  default     = true
}

variable "prefix" {
  description = "Name prefix for the resource group (rg-<prefix>-lab). Lowercase letters and digits."
  type        = string
  default     = "fns"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,9}$", var.prefix))
    error_message = "prefix must be 2-10 lowercase letters or digits, starting with a letter."
  }
}

variable "scope_valid_days" {
  description = "Days until the rendered scope.lab.yaml expires (the scope gate denies everything after)."
  type        = number
  default     = 7

  validation {
    condition     = var.scope_valid_days >= 1 && var.scope_valid_days <= 30
    error_message = "scope_valid_days must be between 1 and 30."
  }
}

variable "github_repository" {
  description = "owner/repo allowed to sign in as the scout identity via GitHub OIDC (main branch only). Empty disables it."
  type        = string
  default     = ""
}
