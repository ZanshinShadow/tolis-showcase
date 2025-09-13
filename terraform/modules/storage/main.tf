# Storage Module - Storage Account and SQL Database

# Random string for unique storage account name
resource "random_string" "storage_suffix" {
  length  = 6
  special = false
  upper   = false
}

# Storage Account
resource "azurerm_storage_account" "main" {
  name                     = "st${var.project_name}${var.environment}${random_string.storage_suffix.result}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  
  # Security settings
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  
  # Network rules
  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [var.subnet_id]
    ip_rules                   = ["0.0.0.0/0"] # Restrict this in production
  }
  
  # Blob properties
  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
    versioning_enabled = true
  }
  
  tags = var.tags
}

# Storage Containers
resource "azurerm_storage_container" "backups" {
  name                  = "backups"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "logs" {
  name                  = "logs"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "scripts" {
  name                  = "scripts"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

# SQL Server
resource "azurerm_mssql_server" "main" {
  name                         = "sql-${var.project_name}-${var.environment}-${random_string.storage_suffix.result}"
  resource_group_name          = var.resource_group_name
  location                     = var.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = random_password.sql_password.result
  
  tags = var.tags
}

# SQL Server Password
resource "random_password" "sql_password" {
  length  = 16
  special = true
}

# SQL Database
resource "azurerm_mssql_database" "main" {
  name           = "db-${var.project_name}-${var.environment}"
  server_id      = azurerm_mssql_server.main.id
  sku_name       = "S0"
  
  # Backup settings
  short_term_retention_policy {
    retention_days = 7
  }
  
  tags = var.tags
}

# SQL Server Firewall Rules
resource "azurerm_mssql_firewall_rule" "azure_services" {
  name             = "AllowAzureServices"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Virtual Network Rule for SQL Server
resource "azurerm_mssql_virtual_network_rule" "main" {
  name      = "sql-vnet-rule"
  server_id = azurerm_mssql_server.main.id
  subnet_id = var.subnet_id
}

# Azure File Share for shared storage
resource "azurerm_storage_share" "main" {
  name                 = "shared-files"
  storage_account_name = azurerm_storage_account.main.name
  quota                = 50
  
  metadata = {
    environment = var.environment
    purpose     = "shared-storage"
  }
}

# Recovery Services Vault for backups
resource "azurerm_recovery_services_vault" "main" {
  name                = "rsv-${var.project_name}-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "Standard"
  
  tags = var.tags
}

# Backup Policy for VMs
resource "azurerm_backup_policy_vm" "main" {
  name                = "vm-backup-policy"
  resource_group_name = var.resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.main.name
  
  backup {
    frequency = "Daily"
    time      = "23:00"
  }
  
  retention_daily {
    count = 10
  }
  
  retention_weekly {
    count    = 42
    weekdays = ["Sunday", "Wednesday", "Friday", "Saturday"]
  }
  
  retention_monthly {
    count    = 7
    weekdays = ["Sunday", "Wednesday"]
    weeks    = ["First", "Last"]
  }
}
