package azure.secure.monitor

import data.azure.monitor.data as d
#default create_policy_assignment = false
#default delete_policy_assignment = false
#default create_update_nsg = false
#default delete_nsg = false
#default create_update_nsg_rule = false
#default delete_nsg_rule = false
#default create_update_security_sol = false
#default delete_security_sol = false
#default create_update_sql_fwr = false

count_total := count(d.monitor_total)

#5.2.1 Ensure that Activity Log Alert exists for Create Policy Assignment
log_create_policy_assignment {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	lower(resource.change.after.criteria[_].category) == "administrative"
	lower(resource.change.after.criteria[_].operation_name) == "microsoft.authorization/policyassignments/write"	
} 
deny[msg] {
	not log_create_policy_assignment == true                                                                 
	msg := "Subscription failed to pass pre-defined 'log_create_policy_assignment' policy"       
}
#5.2.2 Ensure that Activity Log Alert exists for Delete Policy Assignment
log_delete_policy_assignment {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	lower(resource.change.after.criteria[_].category) == "administrative"
	lower(resource.change.after.criteria[_].operation_name) == "microsoft.authorization/policyassignments/delete"	
} 
deny[msg] {
	not log_delete_policy_assignment == true                                                                 
	msg := "Subscription failed to pass pre-defined 'log_delete_policy_assignment' policy"       
}

#5.2.3 Ensure that Activity Log Alert exists for Create or Update Network Security Group
log_create_update_nw_sec_group {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	lower(resource.change.after.criteria[_].category) == "administrative"
	lower(resource.change.after.criteria[_].operation_name) == "microsoft.network/networksecuritygroups/write"	
} 
deny[msg] {
	not log_create_update_nw_sec_group == true                                                                 
	msg := "Subscription failed to pass pre-defined 'log_create_update_nw_sec_group' policy"       
}

#5.2.4 Ensure that Activity Log Alert exists for Delete Network Security Group
log_delete_nw_sec_group {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	lower(resource.change.after.criteria[_].category) == "administrative"
	lower(resource.change.after.criteria[_].operation_name) == "microsoft.network/networksecuritygroups/delete"	
} 
deny[msg] {
	not log_delete_nw_sec_group == true                                                                 
	msg := "Subscription failed to pass pre-defined 'log_delete_nw_sec_group' policy"       
}

#5.2.5 Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule
log_create_update_nw_sec_group_rule {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	lower(resource.change.after.criteria[_].category) == "administrative"
	lower(resource.change.after.criteria[_].operation_name) == "microsoft.network/networksecuritygroups/securityrules/write"	
}
deny[msg] {
	not log_create_update_nw_sec_group_rule == true                                                                 
	msg := "Subscription failed to pass pre-defined 'log_create_update_nw_sec_group_rule' policy"       
} 

#5.2.6 Ensure that activity log alert exists for the Delete Network Security Group Rule
log_delete_nw_sec_group_rule {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	lower(resource.change.after.criteria[_].category) == "administrative"
	lower(resource.change.after.criteria[_].operation_name) == "microsoft.network/networksecuritygroups/securityrules/delete"	
}
deny[msg] {
	not log_delete_nw_sec_group_rule == true                                                                 
	msg := "Subscription failed to pass pre-defined 'log_delete_nw_sec_group_rule' policy"       
} 

#5.2.7 Ensure that Activity Log Alert exists for Create or Update Security Solution
log_create_update_security_sol {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	lower(resource.change.after.criteria[_].category) == "security"
	lower(resource.change.after.criteria[_].operation_name) == "microsoft.security/securitysolutions/write"	
}
deny[msg] {
	not log_create_update_security_sol == true                                                                 
	msg := "Subscription failed to pass pre-defined 'log_create_update_security_sol' policy"       
} 

#5.2.8 Ensure that Activity Log Alert exists for Delete Security Solution
log_delete_security_solution {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	lower(resource.change.after.criteria[_].category) == "security"
	lower(resource.change.after.criteria[_].operation_name) == "microsoft.security/securitysolutions/delete"	
}
deny[msg] {
	not log_delete_security_solution == true                                                                 
	msg := "Subscription failed to pass pre-defined 'log_delete_security_solution' policy"       
} 

#5.2.9 Ensure that Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule
log_create_update_sql_fw_rule {
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	lower(resource.change.after.criteria[_].category) == "administrative"
	lower(resource.change.after.criteria[_].operation_name) == "microsoft.sql/servers/firewallrules/write"	
}
deny[msg] {
	not log_create_update_sql_fw_rule == true                                                                 
	msg := "Subscription failed to pass pre-defined 'log_create_update_sql_fw_rule' policy"       
} 