package azure.authz.storage

import data.oauth


default authz = false



deny[msg] {                                                                 
    name := oauth.users.name                                                            
    oauth.users.roles == "contributer"
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    action := {"update , create"}
    action[resource.change.actions[_]]
	msg := sprintf("'%v'is only allowed to update storage accounts", [name])         
}

authz {
    oauth.users.roles == "contributer"
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    action := {"update" , "no-op"}
    action[resource.change.actions[_]]
    
}

#authz {
#    oauth.users.second.roles == "manager"
#    resource := input.resource_changes[_]
#    resource.type == "azurerm_storage_account"
#    action := {"create" , "update" , "delete"}
#    action[resource.change.actions[_]]
#}
