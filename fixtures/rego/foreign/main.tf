# Exercises the foreign-policy seam with an unmodified public Conftest policy
# (see README.md): one resource per certainty class, plus a passing one and
# an AWS resource that trips two of the policy's rules at once.
variable "encrypt" {
  type = bool
}

data "azurerm_key_vault" "kv" {
  name                = "kv"
  resource_group_name = "rg"
}

# Definite: everything the policy reads is known.
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

# Conditional: the flag comes from an unconstrained variable.
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

# Indeterminate: the flag is only known at apply time.
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
