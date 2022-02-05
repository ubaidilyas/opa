package azure.monitor.data

#List of all app service
monitor_total := { sa |
	resource := input.resource_changes[i]
	resource.type == "azurerm_monitor_activity_log_alert"
	resource.change.actions[_] != "delete"
	sa := resource.change.after.name
} 