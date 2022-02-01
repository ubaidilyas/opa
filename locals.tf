locals {
  nsgrules = {

    rdp = {
      name                       = "rdpdeny"
      priority                   = 100
      direction                  = "Inbound"
      access                     = "Deny"
      protocol                   = "TCP"
      source_port_range          = "*"
      destination_port_range     = "3389"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }

    ssh = {
      name                       = "sshdeny"
      priority                   = 101
      direction                  = "Inbound"
      access                     = "Deny"
      protocol                   = "TCP"
      source_port_range          = "*"
      destination_port_range     = "22"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }

    udp = {
      name                       = "udpdeny"
      priority                   = 102
      direction                  = "Inbound"
      access                     = "Deny"
      protocol                   = "UDP"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
  }

}
