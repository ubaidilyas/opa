package azure.network.data

#List of all nw scurity group
nw_total_sg := { nw |
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_group"
	nw := resource.change.after.name
} 

#List of sql db servers
db_total_sql := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_sql_server"
	db := resource.change.after.name
} 

#List of all network watcher flow log
nw_total_watcher := { nw |
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_watcher_flow_log"
	nw := resource.change.after.network_watcher_name
}

#6.1 Ensure that RDP access is restricted from the internet
nw_rdp_disable := { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_rule"
    resource.change.after.access == "Deny"
    resource.change.after.destination_port_range == "3389"
	nw := resource.change.after.network_security_group_name
}

#6.2 Ensure that SSH access is restricted from the internet
nw_ssh_disable := { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_rule"
    resource.change.after.access == "Deny"
    resource.change.after.destination_port_range == "22"
    nw := resource.change.after.network_security_group_name
}

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
    resource.change.after.retention_policy[_].days >= 90
    nw := resource.change.after.network_watcher_name
}

#6.6 Ensure that UDP Services are restricted from the Internet
nw_udp_disable := { nw | 
	resource := input.resource_changes[i]
	resource.type == "azurerm_network_security_rule"
    resource.change.after.access == "Deny"
    resource.change.after.protocol == "UDP"
    nw := resource.change.after.network_security_group_name
}