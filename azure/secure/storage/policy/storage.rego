package azure.secure.storage

import data.azure.storage.data as d


default secure_transfer = false
default queue_logging = false
default private_blob = false
default deny_default = false
default trusted_microsoft_services = false
default soft_delete = false

#3.1 Ensure that 'Secure transfer required' is set to 'Enabled'
secure_transfer {
	count(d.sa_total) == count(d.sa_secure_transfer)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_secure_transfer
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'secure_transfer' policy", [sa_failed])         
}

#3.3 Ensure Storage logging is enabled for Queue service for read, write, and delete requests
queue_logging {
	count(d.sa_total) == count(d.sa_queue_logging)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_queue_logging
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'queue_logging' policy", [sa_failed])         
}

#3.5 Ensure that 'Public access level' is set to Private for blob containers
private_blob {
	count(d.sc_total) == count(d.sc_private_blob)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_private_blob
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'private_blob' policy", [sa_failed])         
}

#3.6 Ensure default network access rule for Storage Accounts is set to deny
deny_default {
	count(d.sa_total) == count(d.sa_deny_default)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_deny_default
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'deny_default' policy", [sa_failed])         
}

#3.7 Ensure 'Trusted Microsoft Services' is enabled for Storage Account access
trusted_microsoft_services {
	count(d.sa_total) == count(d.sa_microsoft_services)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_microsoft_services
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'trusted_microsoft_services' policy", [sa_failed])         
}

#3.8 Ensure soft delete is enabled for Azure Storage
soft_delete {
	count(d.sa_total) == count(d.sa_soft_delete)
}
deny[msg] {                                                                 
	sa_failed := d.sa_total - d.sa_soft_delete
    count(sa_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'soft_delete' policy", [sa_failed])         
}