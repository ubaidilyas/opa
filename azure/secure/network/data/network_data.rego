package azure.network.data



#List of all nw scurity group
nw_total_sg := { nw |
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_group"
	nw := resource.change.after.name
} 

#List of all nws that pass name
nw_name_sg := { nw |
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_group"
	startswith(resource.change.after.name, "mytf")
	nw := resource.change.after.name
} 

#NWR that have rdp disabled
nw_rdp_disable := { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_rule"
    resource.change.after.access == "Deny"
    resource.change.after.destination_port_range == "3389"
	nw := resource.change.after.network_security_group_name
}

#NWR that have ssh disabled
nw_ssh_disable := { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_rule"
    resource.change.after.access == "Deny"
    resource.change.after.destination_port_range == "22"
    nw := resource.change.after.network_security_group_name

}

#NWR that have udp disabled
nw_udp_disable := { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_rule"
    resource.change.after.access == "Deny"
    resource.change.after.protocol == "UDP"
    nw := resource.change.after.network_security_group_name

}
