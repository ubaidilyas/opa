package azure.authz.vmlinux

import data.oauth


default authz = false



deny[msg] { 
    name := oauth.users.name                                                            
    oauth.users.name == "ubaid"
    resource := input.resource_changes[_]
    resource.type == "azurerm_linux_virtual_machine"
    resource.change.actions[_] == "delete"
	msg := sprintf("'%v'is not allowed to delete virtual machine", [name])       
}

authz {
    oauth.users.name == "ubaid"
    resource := input.resource_changes[_]
    resource.type == "azurerm_linux_virtual_machine"
    action := {"create" , "update" , "no-op"}
    action[resource.change.actions[_]]
}

#authz {
#    oauth.users.second.roles == "manager"
#    resource := input.resource_changes[_]
#    resource.type == "azurerm_linux_virtual_machine"
#    action := {"create" , "update" , "delete"}
 #   action[resource.change.actions[_]]
#}
