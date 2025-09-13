# Output Values for Terraform Configuration

output "resource_group_name" {
  description = "Name of the main resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_location" {
  description = "Location of the main resource group"
  value       = azurerm_resource_group.main.location
}

output "virtual_network_id" {
  description = "ID of the virtual network"
  value       = module.networking.vnet_id
}

output "virtual_network_name" {
  description = "Name of the virtual network"
  value       = module.networking.vnet_name
}

output "subnet_ids" {
  description = "IDs of all subnets"
  value       = module.networking.subnet_ids
}

output "network_security_group_id" {
  description = "ID of the network security group"
  value       = module.networking.nsg_id
}

output "key_vault_id" {
  description = "ID of the Key Vault"
  value       = module.security.key_vault_id
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = module.security.key_vault_uri
}

output "storage_account_name" {
  description = "Name of the storage account"
  value       = module.storage.storage_account_name
}

output "storage_account_primary_endpoint" {
  description = "Primary endpoint of the storage account"
  value       = module.storage.storage_account_primary_endpoint
}

output "virtual_machine_ids" {
  description = "IDs of virtual machines"
  value       = module.compute.vm_ids
}

output "virtual_machine_private_ips" {
  description = "Private IP addresses of virtual machines"
  value       = module.compute.vm_private_ips
}

output "load_balancer_public_ip" {
  description = "Public IP address of the load balancer"
  value       = module.compute.lb_public_ip
  sensitive   = false
}

# Environment Information
output "environment_info" {
  description = "Information about the deployed environment"
  value = {
    environment    = var.environment
    project_name   = var.project_name
    location      = var.location
    deployed_at   = timestamp()
    terraform_version = "~> 1.0"
  }
}

# Cost Management Outputs
output "resource_tags" {
  description = "Common tags applied to resources"
  value       = local.common_tags
}

# Security Information
output "security_info" {
  description = "Security-related information"
  value = {
    key_vault_name = module.security.key_vault_name
    nsg_rules_count = module.networking.nsg_rules_count
  }
  sensitive = false
}
