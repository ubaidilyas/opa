package azure.storage.data


#List of all storage accounts
sa_total := { sa |
	resource := input.resource_changes[i]
	resource.type == "azurerm_storage_account"
	sa := resource.change.after.name
} 

#List of all sa that pass name
sa_name := { sa |
	resource := input.resource_changes[i]
	resource.type == "azurerm_storage_account"
	startswith(resource.change.after.name, "mytf")
	sa := resource.change.after.name
} 


#List of all sa that pass secure transfer
sa_secure_transfer := { sa | 
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	resource.change.after.enable_https_traffic_only == true
	sa := resource.change.after.name
}

#List of all sa that pass private blob
sa_private_blob := { sa |
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	resource.change.after.allow_blob_public_access == false
    sa := resource.change.after.name
} 

#List of all sa that have deny default
sa_deny_default := { sa |
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	resource.change.after.network_rules[0].default_action == "Deny"
    sa := resource.change.after.name
} 

#List of all sa that have microsoft services enabled
sa_microsoft_services := { sa |
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	resource.change.after.network_rules[0].bypass[_] == "AzureServices"
    sa := resource.change.after.name
} 

#List of all sa that have soft delete on
sa_soft_delete := { sa |
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	resource.change.after.blob_properties[0].delete_retention_policy[0].days == 11
    sa := resource.change.after.name
} 