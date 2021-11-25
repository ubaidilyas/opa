package azure.secure.storage

import data.azure.storage.data as d


default secure_transfer = false
default private_blob = false
default deny_default = false
default microsoft_services = false
default soft_delete = false
default standard_name = false


# Checking standard name
standard_name {
	count(d.sa_total) == count(d.sa_name)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_name
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'standard_name' policy", [sa_failed])         
}

#Checking secure transfer enabled
secure_transfer {
	count(d.sa_total) == count(d.sa_secure_transfer)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_secure_transfer
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'secure_transfer' policy", [sa_failed])         
}

#Checking blobs are private
private_blob {
	count(d.sa_total) == count(d.sa_private_blob)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_private_blob
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'private_blob' policy", [sa_failed])         
}

#Checking deny default is enabled
deny_default {
	count(d.sa_total) == count(d.sa_deny_default)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_deny_default
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'deny_default' policy", [sa_failed])         
}

#Checking microsoft services are enabled
microsoft_services {
	count(d.sa_total) == count(d.sa_microsoft_services)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_microsoft_services
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'microsoft_services' policy", [sa_failed])         
}

#Checking soft delete is enabled
soft_delete {
	count(d.sa_total) == count(d.sa_soft_delete)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_soft_delete
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'soft_delete' policy", [sa_failed])         
}

