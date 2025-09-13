# Terraform environment configuration for production
environment    = "prod"
location       = "West Europe"
admin_username = "tolistsadmin"
vm_size        = "Standard_D2s_v3"
vm_count       = 2

# Network configuration
address_space = ["10.1.0.0/16"]
subnets = {
  web = {
    address_prefixes  = ["10.1.1.0/24"]
    service_endpoints = ["Microsoft.KeyVault", "Microsoft.Storage", "Microsoft.Sql"]
  }
  app = {
    address_prefixes  = ["10.1.2.0/24"]
    service_endpoints = ["Microsoft.KeyVault", "Microsoft.Storage", "Microsoft.Sql"]
  }
  data = {
    address_prefixes  = ["10.1.3.0/24"]
    service_endpoints = ["Microsoft.KeyVault", "Microsoft.Storage", "Microsoft.Sql"]
  }
}

# Storage configuration
storage_tier             = "Standard"
storage_replication_type = "ZRS" # Zone-redundant storage for production

# Database configuration
db_sku_name = "GP_Gen5_2" # General Purpose, 2 vCores for production

# Security configuration
key_vault_sku_name = "premium" # Premium tier for production

# Backup configuration
backup_policy_timezone = "W. Europe Standard Time"

# Tags for production environment
tags = {
  Environment = "Production"
  Project     = "Tolis-Showcase"
  Owner       = "Apostolos Tsirogiannidis"
  CostCenter  = "Engineering"
  Compliance  = "Required"
  Backup      = "Daily"
  Monitoring  = "24x7"
}
