output "vnet_id" {
  description = "ID of the virtual network"
  value       = azurerm_virtual_network.main.id
}

output "vnet_name" {
  description = "Name of the virtual network"
  value       = azurerm_virtual_network.main.name
}

output "subnet_id" {
  description = "ID of the web subnet (primary)"
  value       = azurerm_subnet.web.id
}

output "subnet_ids" {
  description = "Map of subnet IDs"
  value = {
    web        = azurerm_subnet.web.id
    app        = azurerm_subnet.app.id
    data       = azurerm_subnet.data.id
    management = azurerm_subnet.management.id
  }
}

output "nsg_id" {
  description = "ID of the network security group"
  value       = azurerm_network_security_group.main.id
}

output "nsg_rules_count" {
  description = "Number of NSG rules configured"
  value       = length(azurerm_network_security_group.main.security_rule)
}
