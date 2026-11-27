# M4 D7: a cost alert on the lab subscription, so a forgotten lab-down turns into
# an email. Created only when budget_alert_email is set (terraform.tfvars, which
# is gitignored), and destroyed by lab-down with everything else.
#
# Microsoft lists Azure for Students (MS-AZR-0170P) among the offers Cost
# Management does not support. On such a subscription leave budget_alert_email
# empty: lab/README.md, "Cost alert", has what to do instead.

locals {
  budget_enabled = var.budget_alert_email != ""
}

# Budgets start on the first day of a month. time_static fixes "now" at create
# time, so later plans do not move the start date.
resource "time_static" "budget_start" {
  count = local.budget_enabled ? 1 : 0
}

resource "azurerm_consumption_budget_subscription" "lab" {
  count = local.budget_enabled ? 1 : 0

  name            = "budget-${var.prefix}-lab"
  subscription_id = "/subscriptions/${var.subscription_id}"
  amount          = var.budget_amount
  time_grain      = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", time_static.budget_start[0].rfc3339)
  }

  notification {
    enabled        = true
    operator       = "GreaterThanOrEqualTo"
    threshold      = 50
    threshold_type = "Actual"
    contact_emails = [var.budget_alert_email]
  }

  notification {
    enabled        = true
    operator       = "GreaterThanOrEqualTo"
    threshold      = 100
    threshold_type = "Actual"
    contact_emails = [var.budget_alert_email]
  }

  notification {
    enabled        = true
    operator       = "GreaterThanOrEqualTo"
    threshold      = 100
    threshold_type = "Forecasted"
    contact_emails = [var.budget_alert_email]
  }
}
