package azure.secure.monitor

default create_policy_assignment = false
default delete_policy_assignment = false
default create_update_nsg = false
default delete_nsg = false
default create_update_nsg_rule = false
default delete_nsg_rule = false
default create_update_security_sol = false
default delete_security_sol = false
default create_update_sql_fwr = false

#5.2.1 Ensure that Activity Log Alert exists for Create Policy Assignment
create_policy_assignment {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.after.criteria[_].category == "Administrative"
	resource.change.after.criteria[_].operation_name == "Microsoft.Authorization/policyAssignments/write"	
} 
deny[msg] {
	create_policy_assignment == false                                                                 
	msg := "Subscription failed to pass pre-defined 'create_policy_assignment' policy"       
}
#5.2.2 Ensure that Activity Log Alert exists for Delete Policy Assignment
delete_policy_assignment {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.after.criteria[_].category == "Administrative"
	resource.change.after.criteria[_].operation_name == "Microsoft.Authorization/policyAssignments/delete"	
} 
deny[msg] {
	delete_policy_assignment == false                                                                 
	msg := "Subscription failed to pass pre-defined 'delete_policy_assignment' policy"       
}

#5.2.3 Ensure that Activity Log Alert exists for Create or Update Network Security Group
create_update_nsg {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.after.criteria[_].category == "Administrative"
	resource.change.after.criteria[_].operation_name == "Microsoft.Network/networkSecurityGroups/write"	
} 
deny[msg] {
	create_update_nsg == false                                                                 
	msg := "Subscription failed to pass pre-defined 'create_update_nsg' policy"       
}

#5.2.4 Ensure that Activity Log Alert exists for Delete Network Security Group
delete_nsg {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.after.criteria[_].category == "Administrative"
	resource.change.after.criteria[_].operation_name == "Microsoft.Network/networkSecurityGroups/delete"	
} 
deny[msg] {
	delete_nsg == false                                                                 
	msg := "Subscription failed to pass pre-defined 'delete_nsg' policy"       
}

#5.2.5 Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule
create_update_nsg_rule {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.after.criteria[_].category == "Administrative"
	resource.change.after.criteria[_].operation_name == "Microsoft.Network/networkSecurityGroups/securityRules/write"	
}
deny[msg] {
	create_update_nsg_rule == false                                                                 
	msg := "Subscription failed to pass pre-defined 'create_update_nsg_rule' policy"       
} 

#5.2.6 Ensure that activity log alert exists for the Delete Network Security Group Rule
delete_nsg_rule {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.after.criteria[_].category == "Administrative"
	resource.change.after.criteria[_].operation_name == "Microsoft.Network/networkSecurityGroups/securityRules/delete"	
}
deny[msg] {
	delete_nsg_rule == false                                                                 
	msg := "Subscription failed to pass pre-defined 'delete_nsg_rule' policy"       
} 

#5.2.7 Ensure that Activity Log Alert exists for Create or Update Security Solution
create_update_security_sol {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.after.criteria[_].category == "Security"
	resource.change.after.criteria[_].operation_name == "Microsoft.Security/securitySolutions/write"	
}
deny[msg] {
	create_update_security_sol == false                                                                 
	msg := "Subscription failed to pass pre-defined 'create_update_security_sol' policy"       
} 

#5.2.8 Ensure that Activity Log Alert exists for Delete Security Solution
delete_security_sol {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.after.criteria[_].category == "Security"
	resource.change.after.criteria[_].operation_name == "Microsoft.Security/securitySolutions/delete"	
}
deny[msg] {
	delete_security_sol == false                                                                 
	msg := "Subscription failed to pass pre-defined 'delete_security_sol' policy"       
} 

#5.2.9 Ensure that Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule
create_update_sql_fwr {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.after.criteria[_].category == "Administrative"
	resource.change.after.criteria[_].operation_name == "Microsoft.Sql/servers/firewallRules/write"	
}
deny[msg] {
	create_update_sql_fwr == false                                                                 
	msg := "Subscription failed to pass pre-defined 'create_update_sql_fwr' policy"       
} 