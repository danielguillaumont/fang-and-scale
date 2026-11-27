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

variable "budget_alert_email" {
  description = "Where the lab budget alert goes (M4 D7). Empty: no budget. Set it in terraform.tfvars only, never in a committed file."
  type        = string
  default     = ""
  sensitive   = true

  validation {
    condition     = var.budget_alert_email == "" || can(regex("^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$", var.budget_alert_email))
    error_message = "budget_alert_email must be empty or one email address."
  }
}

variable "budget_amount" {
  description = "Monthly lab budget in the billing currency (M4 D7). Alerts at 50% and 100% actual, and 100% forecast."
  type        = number
  default     = 10

  validation {
    condition     = var.budget_amount >= 1 && var.budget_amount <= 100
    error_message = "budget_amount must be between 1 and 100."
  }
}

variable "enable_monitoring" {
  description = "M4 sessions B to D: a Log Analytics workspace with Sentinel, diagnostic settings for the Activity Log, Key Vault, blobs and Entra, and the rules from detections/ (lab/monitoring.tf). Starting Sentinel starts its 31-day trial."
  type        = bool
  default     = false
}

variable "monitoring_daily_quota_gb" {
  description = "Daily ingestion cap of the lab workspace in GB (M4). The lab logs megabytes a day; the cap only limits a runaway."
  type        = number
  default     = 1

  validation {
    condition     = var.monitoring_daily_quota_gb >= 0.1 && var.monitoring_daily_quota_gb <= 10
    error_message = "monitoring_daily_quota_gb must be between 0.1 and 10."
  }
}

variable "enable_strikes" {
  description = "Render the strike: block into scope.lab.yaml (M4 sessions C and D). Off: the scope stays read-only."
  type        = bool
  default     = false
}

variable "strike_valid_hours" {
  description = "Hours the strike: block is valid after it is rendered (re-render with -replace=time_offset.strike_expiry)."
  type        = number
  default     = 4

  validation {
    condition     = var.strike_valid_hours >= 1 && var.strike_valid_hours <= 24
    error_message = "strike_valid_hours must be between 1 and 24."
  }
}
