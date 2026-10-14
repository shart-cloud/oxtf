# Pinned provider versions for schema snapshots (spike W2).
# Latest release of each target major as of 2026-10-14 (google: latest overall, 8.x).
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.68.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 5.9.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "= 8.7.0"
    }
  }
}
