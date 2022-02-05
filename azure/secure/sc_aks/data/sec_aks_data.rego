package azure.sec_aks.data

#List of all aks
aks_total := { aks |
	resource := input.resource_changes[i]
	resource.type == "azurerm_kubernetes_cluster"
	resource.change.actions[_] != "delete"
	aks := resource.change.after.name
} 

#List of all kv
kv_total := { kv |
	resource := input.resource_changes[i]
	resource.type == "azurerm_key_vault"
	resource.change.actions[_] != "delete"
	kv := resource.change.after.name
} 

#List of all kv_key
kv_key_total := { kv |
	resource := input.resource_changes[i]
	resource.type == "azurerm_key_vault_key"
	resource.change.actions[_] != "delete"
	kv := resource.change.after.name
} 

#List of all kv_secret
kv_secret_total := { kv |
	resource := input.resource_changes[i]
	resource.type == "azurerm_key_vault_secret"
	resource.change.actions[_] != "delete"
	kv := resource.change.after.name
} 

sec_auto_pro_total := { sec |
	resource := input.resource_changes[i]
	resource.type == "azurerm_security_center_auto_provisioning"
	resource.change.actions[_] != "delete"
	sec := resource.name
} 

#2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On'
sec_auto_pro := { sec |
	resource := input.resource_changes[i]
	resource.type == "azurerm_security_center_auto_provisioning"
	resource.change.after.auto_provision == "On"
	sec := resource.name
} 	

#8.1 Ensure that the expiration date is set on all keys
kv_key_expire := { kv |
	resource := input.resource_changes[i]
	resource.type == "azurerm_key_vault_key"
	resource.change.after.expiration_date != null
	kv := resource.change.after.name
} 

#8.2 Ensure that the expiration date is set on all Secrets
kv_secret_expire := { kv |
	resource := input.resource_changes[i]
	resource.type == "azurerm_key_vault_secret"
	resource.change.after.expiration_date != null
	kv := resource.change.after.name
} 

#8.4 Ensure the key vault is recoverable
kv_recover := { kv |
	resource := input.resource_changes[i]
	resource.type == "azurerm_key_vault"
	resource.change.after.purge_protection_enabled == true
	kv := resource.change.after.name
}

#8.5 Enable role-based access control (RBAC) within Azure Kubernetes Services
aks_rbac_en := { aks |
	resource := input.resource_changes[i]
	resource.type == "azurerm_kubernetes_cluster"
	resource.change.after.role_based_access_control[_].enabled=true
    aks := resource.change.after.name
} 

aks_rbac_na := { aks |
    resource := input.resource_changes[i]
	resource.type == "azurerm_kubernetes_cluster"
	not resource.change.after.role_based_access_control
    aks := resource.change.after.name
}