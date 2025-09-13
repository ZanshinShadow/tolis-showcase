# Security Module - Key Vault and Security Configurations

# Get current client configuration
data "azurerm_client_config" "current" {}

# Random string for unique naming
resource "random_string" "keyvault_suffix" {
  length  = 4
  special = false
  upper   = false
}

# Azure Key Vault
resource "azurerm_key_vault" "main" {
  name                = "kv-${var.project_name}-${var.environment}-${random_string.keyvault_suffix.result}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id

  sku_name = "standard"

  # Security enhancements for showcase
  soft_delete_retention_days = 90
  purge_protection_enabled   = true # CKV_AZURE_110
  enable_rbac_authorization  = false

  # Access policies
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get", "List", "Update", "Create", "Import", "Delete", "Recover", "Backup", "Restore"
    ]

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Recover", "Backup", "Restore"
    ]

    certificate_permissions = [
      "Get", "List", "Update", "Create", "Import", "Delete", "Recover", "Backup", "Restore", "ManageContacts", "ManageIssuers", "GetIssuers", "ListIssuers", "SetIssuers", "DeleteIssuers"
    ]
  }

  # Network access rules
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"

    virtual_network_subnet_ids = [var.subnet_id]

    # Allow access from management subnet
    ip_rules = ["0.0.0.0/0"] # Restrict this in production
  }

  # Security features
  enabled_for_disk_encryption     = true
  enabled_for_template_deployment = true
  enabled_for_deployment          = true

  tags = var.tags
}

# Key Vault Secrets for demonstration
resource "azurerm_key_vault_secret" "admin_username" {
  name         = "admin-username"
  value        = "azureadmin"
  key_vault_id = azurerm_key_vault.main.id
  content_type = "username" # CKV_AZURE_114

  depends_on = [azurerm_key_vault.main]
}

resource "azurerm_key_vault_secret" "database_connection_string" {
  name         = "database-connection-string"
  value        = "Server=tcp:sql-${var.project_name}-${var.environment}.database.windows.net,1433;Database=db-${var.project_name};Encrypt=true;TrustServerCertificate=false;Connection Timeout=30;"
  key_vault_id = azurerm_key_vault.main.id
  content_type = "connection-string" # CKV_AZURE_114

  depends_on = [azurerm_key_vault.main]
}

# Generate SSH Key for Linux VMs
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "azurerm_key_vault_secret" "ssh_private_key" {
  name         = "ssh-private-key"
  value        = tls_private_key.ssh_key.private_key_pem
  key_vault_id = azurerm_key_vault.main.id
  
  depends_on = [azurerm_key_vault.main]
}

resource "azurerm_key_vault_secret" "ssh_public_key" {
  name         = "ssh-public-key"
  value        = tls_private_key.ssh_key.public_key_openssh
  key_vault_id = azurerm_key_vault.main.id
  
  depends_on = [azurerm_key_vault.main]
}

# Security Center (Defender for Cloud) - Optional
# Uncomment if you want to enable Azure Defender
/*
resource "azurerm_security_center_subscription_pricing" "main" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_contact" "main" {
  email               = "apostolis.tsirogiannis@techtakt.com"
  phone               = "+1-555-555-5555"
  alert_notifications = true
  alerts_to_admins    = true
}
*/

# Log Analytics Workspace for security monitoring
resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.project_name}-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  
  tags = var.tags
}

# Security solutions
resource "azurerm_log_analytics_solution" "security" {
  solution_name         = "Security"
  location              = var.location
  resource_group_name   = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.main.id
  workspace_name        = azurerm_log_analytics_workspace.main.name
  
  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/Security"
  }
}

resource "azurerm_log_analytics_solution" "updates" {
  solution_name         = "Updates"
  location              = var.location
  resource_group_name   = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.main.id
  workspace_name        = azurerm_log_analytics_workspace.main.name
  
  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/Updates"
  }
}
