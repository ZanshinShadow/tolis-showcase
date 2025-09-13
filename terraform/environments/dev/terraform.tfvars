# Development Environment Configuration

project_name   = "tolis-showcase"
environment    = "dev"
location       = "East US"
location_short = "eus"
owner          = "Apostolos Tsirogiannis (Tolis)"
cost_center    = "IT-Development"

# Networking
vnet_address_space = ["10.0.0.0/16"]

# Compute
vm_size = "Standard_B2s"

# Storage
storage_account_tier     = "Standard"
storage_replication_type = "LRS"

# Database
sql_server_version = "12.0"
sql_database_sku   = "S0"

# Security - Restrict these in production
allowed_ip_ranges = [
  "0.0.0.0/0" # Replace with your actual IP ranges
]

enable_ddos_protection = false
