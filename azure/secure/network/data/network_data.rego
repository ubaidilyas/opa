package azure.network.data

#List of all nw scurity group
nw_total_sg := { nw |
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_group"
	resource.change.actions[_] != "delete"
	nw := resource.change.after.name
} 

#List of sql db servers
db_total_sql := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_sql_server"
	resource.change.actions[_] != "delete"
	db := resource.change.after.name
} 

#List of all network watcher flow log
nw_total_watcher := { nw |
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_watcher_flow_log"
	resource.change.actions[_] != "delete"
	nw := resource.change.after.network_watcher_name
}

#6.1 Ensure that RDP access is restricted from the internet

nw_rdp_enable_nsr:= { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_rule"
    helper_function_rdp_ssh(resource.change.after,"3389")
	nw := resource.change.after.network_security_group_name
}
nw_rdp_enable_nsg:= { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_group"
    helper_function_rdp_ssh(resource.change.after.security_rule[_],"3389")
	nw := resource.change.after.name
}


#6.2 Ensure that SSH access is restricted from the internet

nw_ssh_enable_nsr:= { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_rule"
    helper_function_rdp_ssh(resource.change.after,"22")
	nw := resource.change.after.network_security_group_name
}
nw_ssh_enable_nsg:= { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_group"
    helper_function_rdp_ssh(resource.change.after.security_rule[_],"22")
	nw := resource.change.after.name
}


# Helper function for 6.1 and 6.2
helper_function_rdp_ssh(base,port){
	lower(base.access) == "allow"
	lower(base.direction) == "inbound"
	lower(base.protocol) == "tcp"
	source_address(base)
	destination_port(base,port)
}

destination_port(base,port){
destination_port_range(base.destination_port_range,port)
}{
destination_port_range(base.destination_port_ranges[_],port)
}

destination_port_range(des_port,port){
	des_port == port
}{
	des_port == "*"
}{
	range := split(des_port,"-")
	to_number(range[0]) <= to_number(3389)
	to_number(range[1]) >= to_number(3389)
}

source_address(base){
	source_addresses[lower(base.source_address_prefix)]
}{
	source_addresses[lower(base.source_address_prefixes[_])]
}

source_addresses := {"*", "0.0.0.0", "0.0.0.0/0", "::/0", "internet", "any"}

#6.3 Ensure no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)
db_sqlfwr := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_sql_firewall_rule"
	resource.change.after.end_ip_address == "0.0.0.0"
	resource.change.after.start_ip_address == "0.0.0.0"
	db := resource.change.after.server_name
} 

#6.4 Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'
nw_flow_log := { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_watcher_flow_log"
    to_number(resource.change.after.retention_policy[_].days) >= 90
    nw := resource.change.after.network_watcher_name
}

#6.6 Ensure that UDP Services are restricted from the Internet

nw_udp_enable_nsr:= { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_rule"
    helper_function_udp(resource.change.after)
	nw := resource.change.after.network_security_group_name
}
nw_udp_enable_nsg:= { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_group"
    helper_function_udp(resource.change.after.security_rule[_])
	nw := resource.change.after.name
}

# Helper function for 6.6
helper_function_udp(base){
	lower(base.access) == "allow"
	lower(base.direction) == "inbound"
	lower(base.protocol) == "udp"
	source_address(base)
}