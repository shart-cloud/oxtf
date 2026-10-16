# Encrypted. The public policy still flags it under Conftest, because hcl2json
# renders the block as a list and `not <undefined path>` is true; see rego.rs.
resource "azurerm_managed_disk" "ok" {
  name                 = "ok"
  location             = "westeurope"
  resource_group_name  = "rg"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  encryption_settings {
    enabled = true
  }
}
