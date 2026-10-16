# Indeterminate: the flag is only known at apply time.
data "azurerm_key_vault" "kv" {
  name                = "kv"
  resource_group_name = "rg"
}

resource "azurerm_managed_disk" "from_data" {
  name                 = "from-data"
  location             = "westeurope"
  resource_group_name  = "rg"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  encryption_settings {
    enabled = data.azurerm_key_vault.kv.enabled_for_disk_encryption
  }
}
