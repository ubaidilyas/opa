package azure.secure.sec_aks

import data.azure.sec_aks.data as d


default sec_auto_provisioning_on = true 
default sec_additional_contact = false
default sec_severity_high = false
default sec_role_owner = false
default key_expiration = false
default secret_expiration = false
default kv_recoverable = false
default rbac_enabled_aks = false

#2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On'
sec_auto_provisioning_on = false {
	resource := input.resource_changes[i]
	resource.type == "azurerm_security_center_auto_provisioning"
	resource.change.after.auto_provision == "Off"
}
deny[msg] {                                                                 
	sec_auto_provisioning = false
	msg := "Subscription failed to pass pre-defined 'sec_auto_provisioning' policy"       
}

#2.13 Ensure 'Additional email addresses' is configured with a security contact email
sec_additional_contact {
	resource := input.resource_changes[i]
	resource.type == "azurerm_security_center_contact"
	resource.change.after.email != null
} 
deny[msg] {                                                                 
	sec_additional_contact = false
	msg := "Subscription failed to pass pre-defined 'sec_additional_contact' policy"       
}

#2.14 Ensure that 'Notify about alerts with the following severity' is set to 'High'
sec_severity_high {
	resource := input.resource_changes[i]
	resource.type == "azurerm_security_center_contact"
	resource.change.after.alert_notifications == true
} 
deny[msg] {                                                                 
	sec_severity_high = false
	msg := "Subscription failed to pass pre-defined 'sec_severity_high' policy"       
}

#2.15 Ensure that 'All users with the following roles' is set to 'Owner'
sec_role_owner {
	resource := input.resource_changes[i]
	resource.type == "azurerm_security_center_contact"
	resource.change.after.alerts_to_admins == true
} 
deny[msg] {                                                                 
	sec_role_owner = false
	msg := "Subscription failed to pass pre-defined 'sec_role_owner' policy"       
}

#8.1 Ensure that the expiration date is set on all keys
key_expiration {
	count(d.kv_key_total) == count(d.kv_key_expire)
}
deny[msg] {                                                                 
	kv_failed := d.kv_key_total - d.kv_key_expire
    count(kv_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'key_expiration' policy", [kv_failed])         
}

#8.2 Ensure that the expiration date is set on all Secrets
secret_expiration {
	count(d.kv_secret_total) == count(d.kv_secret_expire)
}
deny[msg] {                                                                 
	kv_failed := d.kv_secret_total - d.kv_secret_expire
    count(kv_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'secret_expiration' policy", [kv_failed])         
}

#8.4 Ensure the key vault is recoverable
kv_recoverable {
	count(d.kv_total) == count(d.kv_recover)
}
deny[msg] {                                                                 
	kv_failed := d.kv_total - d.kv_recover
    count(kv_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'kv_recoverable' policy", [kv_failed])         
}

#8.5 Enable role-based access control (RBAC) within Azure Kubernetes Services
rbac_enabled_aks {
	count(d.aks_total) == count(d.aks_rbac_en) + count(d.aks_rbac_na)
}
deny[msg] {                                                                 
	aks_checked_all := d.aks_rbac_en | d.aks_rbac_na
	aks_failed := d.aks_total - aks_checked_all
    count(aks_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'rbac_enabled_aks' policy", [aks_failed])         
}