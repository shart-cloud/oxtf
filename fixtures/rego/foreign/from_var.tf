# Conditional: the flag comes from an unconstrained variable.
variable "encrypt" {
  type = bool
}

resource "azurerm_managed_disk" "from_var" {
  name                 = "from-var"
  location             = "westeurope"
  resource_group_name  = "rg"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  encryption_settings {
    enabled = var.encrypt
  }
}
