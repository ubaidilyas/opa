package azure.secure.vmlinux

import data.azure.vmlinux.data as d

default size_accept = false
default version_latest = false
default managed_disks = false
default standard_name = false

# Checking standard name
standard_name {
	count(d.vm_total) == count(d.vm_name)
}
deny[msg] {                                                                 
	vm_failed := d.vm_total - d.vm_name
    count(vm_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'standard_name' policy", [vm_failed])         
}

#Checking standard size
size_accept {
	count(d.vm_total) == count(d.vm_default) + count(d.vm_exception)
}
deny[msg] {                                                                 
	vm_checked_all := d.vm_default | d.vm_exception
	vm_failed := d.vm_total - vm_checked_all
    count(vm_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'size_accept' policy", [vm_failed])         
}

#Checking latest version
version_latest {
	count(d.vm_total) == count(d.vm_version)
}
deny[msg] {                                                                 
	vm_failed := d.vm_total - d.vm_version
    count(vm_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'version_latest' policy", [vm_failed])         
}

#Checking managed disk
managed_disks {
	count(d.vm_total) == count(d.vm_managed)
}
deny[msg] {                                                                 
	vm_failed := d.vm_total - d.vm_managed
    count(vm_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'managed_disks' policy", [vm_failed])         
}