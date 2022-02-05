package azure.iam.data

#List of iam roles
iam_total_roles := { iam |
	resource := input.resource_changes[i]
	resource.type == "azurerm_role_definition"
  resource.change.actions[_] != "delete"
  iam := resource.change.after.name
} 

#1.21 Ensure that no custom subscription owner roles are created
iam_sub_owner := { iam |
	resource := input.resource_changes[i]
	resource.type == "azurerm_role_definition"
	resource.change.after.permissions[_].actions[_] == "*"
  scope_sub(resource.change.after.scope)
  iam := resource.change.after.name
} 
scope_sub(sub) {
  sub == "/"
} {
  regex.match("^/subscriptions/[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$", sub)
}
