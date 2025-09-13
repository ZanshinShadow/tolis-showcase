# Senior System Engineer Showcase - Azure Infrastructure
# This configuration demonstrates enterprise-level Terraform practices

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
  
  # Backend configuration for remote state (production use)
  backend "azurerm" {
    # Configure these values in terraform init
    # resource_group_name  = "rg-terraform-state"
    # storage_account_name = "stterraformstate"
    # container_name       = "tfstate"
    # key                  = "showcase.terraform.tfstate"
  }
}

# Azure Provider Configuration
provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

provider "azuread" {}

# Local values for common configurations
locals {
  environment = var.environment
  location    = var.location
  
  # Standardized naming convention
  naming_convention = {
    resource_group = "rg-${var.project_name}-${local.environment}-${var.location_short}"
    key_vault     = "kv-${var.project_name}-${local.environment}-${random_string.suffix.result}"
    storage       = "st${var.project_name}${local.environment}${random_string.suffix.result}"
    app_service   = "app-${var.project_name}-${local.environment}-${var.location_short}"
    sql_server    = "sql-${var.project_name}-${local.environment}-${var.location_short}"
  }
  
  # Common tags for all resources
  common_tags = {
    Environment   = local.environment
    Project      = var.project_name
    ManagedBy    = "Terraform"
    Owner        = var.owner
    CostCenter   = var.cost_center
    CreatedDate  = formatdate("YYYY-MM-DD", timestamp())
  }
}

# Random string for unique naming
resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

# Main Resource Group
resource "azurerm_resource_group" "main" {
  name     = local.naming_convention.resource_group
  location = local.location
  tags     = local.common_tags
}

# Call modules for different components
module "networking" {
  source = "./modules/networking"
  
  resource_group_name = azurerm_resource_group.main.name
  location           = azurerm_resource_group.main.location
  environment        = local.environment
  project_name       = var.project_name
  tags              = local.common_tags
}

module "security" {
  source = "./modules/security"
  
  resource_group_name = azurerm_resource_group.main.name
  location           = azurerm_resource_group.main.location
  environment        = local.environment
  project_name       = var.project_name
  tags              = local.common_tags
  
  subnet_id = module.networking.subnet_id
}

module "compute" {
  source = "./modules/compute"
  
  resource_group_name     = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  environment            = local.environment
  project_name           = var.project_name
  tags                  = local.common_tags
  
  subnet_id             = module.networking.subnet_id
  key_vault_id          = module.security.key_vault_id
  network_security_group_id = module.networking.nsg_id
}

module "storage" {
  source = "./modules/storage"
  
  resource_group_name = azurerm_resource_group.main.name
  location           = azurerm_resource_group.main.location
  environment        = local.environment
  project_name       = var.project_name
  tags              = local.common_tags
  
  subnet_id = module.networking.subnet_id
}
