# Pinned provider versions for schema snapshots (spike W2).
# Latest release of each target major as of 2026-10-14 (google: latest overall, 8.x;
# cloudflare, kubernetes, github: latest overall, added 2026-10-14).
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
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 5.28.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "= 3.3.0"
    }
    github = {
      source  = "integrations/github"
      version = "= 6.13.0"
    }
  }
}
