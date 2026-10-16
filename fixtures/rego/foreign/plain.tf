# Definite: everything the policy reads in this file is known. Conftest
# evaluates one file at a time, so each certainty class has its own file.
resource "azurerm_managed_disk" "plain" {
  name                 = "plain"
  location             = "westeurope"
  resource_group_name  = "rg"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  encryption_settings {
    enabled = false
  }
}
