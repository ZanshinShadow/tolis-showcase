# Compute Module - Virtual Machines and Load Balancer

# Public IP for Load Balancer
resource "azurerm_public_ip" "lb" {
  name                = "pip-lb-${var.project_name}-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                = "Standard"
  
  tags = var.tags
}

# Load Balancer
resource "azurerm_lb" "main" {
  name                = "lb-${var.project_name}-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                = "Standard"
  
  frontend_ip_configuration {
    name                 = "PublicIPAddress"
    public_ip_address_id = azurerm_public_ip.lb.id
  }
  
  tags = var.tags
}

# Backend Address Pool
resource "azurerm_lb_backend_address_pool" "main" {
  loadbalancer_id = azurerm_lb.main.id
  name            = "BackEndAddressPool"
}

# Health Probe
resource "azurerm_lb_probe" "main" {
  loadbalancer_id = azurerm_lb.main.id
  name            = "http-probe"
  port            = 80
  protocol        = "Http"
  request_path    = "/"
}

# Load Balancer Rule
resource "azurerm_lb_rule" "main" {
  loadbalancer_id                = azurerm_lb.main.id
  name                           = "LBRule"
  protocol                       = "Tcp"
  frontend_port                  = 80
  backend_port                   = 80
  frontend_ip_configuration_name = "PublicIPAddress"
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.main.id]
  probe_id                       = azurerm_lb_probe.main.id
}

# Availability Set
resource "azurerm_availability_set" "main" {
  name                = "avset-${var.project_name}-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  
  platform_fault_domain_count  = 2
  platform_update_domain_count = 2
  managed                      = true
  
  tags = var.tags
}

# Network Interfaces for VMs
resource "azurerm_network_interface" "vm" {
  count               = 2
  name                = "nic-vm-${count.index + 1}-${var.project_name}-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  
  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
  
  tags = var.tags
}

# Associate NICs with Backend Pool
resource "azurerm_network_interface_backend_address_pool_association" "main" {
  count                   = 2
  network_interface_id    = azurerm_network_interface.vm[count.index].id
  ip_configuration_name   = "internal"
  backend_address_pool_id = azurerm_lb_backend_address_pool.main.id
}

# Associate NICs with NSG
resource "azurerm_network_interface_security_group_association" "main" {
  count                     = 2
  network_interface_id      = azurerm_network_interface.vm[count.index].id
  network_security_group_id = var.network_security_group_id
}

# Get SSH key from Key Vault
data "azurerm_key_vault_secret" "ssh_key" {
  name         = "ssh-public-key"
  key_vault_id = var.key_vault_id
}

# Virtual Machines
resource "azurerm_linux_virtual_machine" "vm" {
  count               = 2
  name                = "vm-${count.index + 1}-${var.project_name}-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = "Standard_B2s"
  admin_username      = "azureadmin"
  availability_set_id = azurerm_availability_set.main.id
  
  # Disable password authentication
  disable_password_authentication = true
  
  network_interface_ids = [
    azurerm_network_interface.vm[count.index].id,
  ]
  
  admin_ssh_key {
    username   = "azureadmin"
    public_key = data.azurerm_key_vault_secret.ssh_key.value
  }
  
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    # Encryption settings for showcase - using VMGuestStateOnly for demo purposes
    security_encryption_type = "VMGuestStateOnly"
  }
  
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts-gen2"
    version   = "latest"
  }
  
  # Custom data for initial setup
  custom_data = base64encode(templatefile("${path.module}/cloud-init.yaml", {
    vm_name = "vm-${count.index + 1}-${var.project_name}-${var.environment}"
  }))
  
  tags = var.tags
}

# Managed Disks for additional storage
resource "azurerm_managed_disk" "data" {
  count                = 2
  name                 = "disk-data-vm-${count.index + 1}-${var.project_name}-${var.environment}"
  location             = var.location
  resource_group_name  = var.resource_group_name
  storage_account_type = "Premium_LRS"
  create_option        = "Empty"
  disk_size_gb         = 64
  
  # Security enhancements for showcase
  public_network_access_enabled = false # CKV_AZURE_251
  network_access_policy         = "DenyAll"
  
  tags = var.tags
}

# Attach data disks to VMs
resource "azurerm_virtual_machine_data_disk_attachment" "data" {
  count              = 2
  managed_disk_id    = azurerm_managed_disk.data[count.index].id
  virtual_machine_id = azurerm_linux_virtual_machine.vm[count.index].id
  lun                = "0"
  caching            = "ReadWrite"
}
