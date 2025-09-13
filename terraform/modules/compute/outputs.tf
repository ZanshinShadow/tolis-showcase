output "vm_ids" {
  description = "IDs of the virtual machines"
  value       = azurerm_linux_virtual_machine.vm[*].id
}

output "vm_private_ips" {
  description = "Private IP addresses of the virtual machines"
  value       = azurerm_network_interface.vm[*].private_ip_address
}

output "lb_public_ip" {
  description = "Public IP address of the load balancer"
  value       = azurerm_public_ip.lb.ip_address
}

output "vm_names" {
  description = "Names of the virtual machines"
  value       = azurerm_linux_virtual_machine.vm[*].name
}
