package azure.authz.network

deny [msg]{
	resource := input.resource_changes[_]
	resource.type == "azurerm_network_security_group"
	name := resource.type
	msg := sprintf("No authorization rules for '%v'", [name])   
}
