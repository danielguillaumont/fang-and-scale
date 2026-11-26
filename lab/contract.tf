# Renders ../contracts/lab/billing-agent.fns.yaml (gitignored): the seeded
# contract with this lab's real resource names (they carry a random suffix).
# docs/milestones/M2.md, decision D5.

resource "local_file" "contract" {
  filename        = "${path.module}/../contracts/lab/billing-agent.fns.yaml"
  file_permission = "0644"
  content = templatefile("${path.module}/contract.lab.fns.yaml.tftpl", {
    agent    = azuread_application.billing_agent.display_name
    vault    = azurerm_key_vault.crown_jewels.name
    payroll  = azurerm_storage_account.payroll.name
    invoices = azurerm_storage_account.invoices.name
    verifier = azuread_application.verifier.display_name
    scout    = azuread_application.scout.display_name
  })
}
