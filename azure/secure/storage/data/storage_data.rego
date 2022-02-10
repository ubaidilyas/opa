package azure.storage.data


#List of all storage accounts and storage containers
sa_total := { sa |
	resource := input.resource_changes[i]
	resource.type == "azurerm_storage_account"
	resource.change.actions[_] != "delete"
	sa := resource.change.after.name
} 

sc_total := { sc |
	resource := input.resource_changes[i]
	resource.type == "azurerm_storage_container"
	resource.change.actions[_] != "delete"
	sc := resource.change.after.name
} 

#3.1 Ensure that 'Secure transfer required' is set to 'Enabled'
sa_secure_transfer := { sa | 
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	resource.change.after.enable_https_traffic_only == true
	sa := resource.change.after.name
}

#3.3 Ensure Storage logging is enabled for Queue service for read, write, and delete requests
sa_queue_logging := { sa | 
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	resource.change.after.queue_properties[_].logging[_].read == true
	resource.change.after.queue_properties[_].logging[_].write == true
	resource.change.after.queue_properties[_].logging[_].delete == true
	sa := resource.change.after.name
}

#3.5 Ensure that 'Public access level' is set to Private for blob containers
sc_private_blob := { sc |
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_container"
	lower(resource.change.after.container_access_type) == "private"
    sc := resource.change.after.name
} 

#3.6 Ensure default network access rule for Storage Accounts is set to deny
sa_deny_default := { sa |
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	lower(resource.change.after.network_rules[_].default_action) == "deny"
    sa := resource.change.after.name
}

#3.7 Ensure 'Trusted Microsoft Services' is enabled for Storage Account access
sa_microsoft_services := { sa |
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	lower(resource.change.after.network_rules[_].bypass[_]) == "azureservices"
	sa := resource.change.after.name
} 

#3.8 Ensure soft delete is enabled for Azure Storage
sa_soft_delete := { sa |
	resource := input.resource_changes[_]
	resource.type == "azurerm_storage_account"
	to_number(resource.change.after.blob_properties[_].delete_retention_policy[_].days) >= 7
    sa := resource.change.after.name
} 
