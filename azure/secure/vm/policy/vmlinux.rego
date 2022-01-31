package azure.secure.vm

import data.azure.vm.data as d

default managed_disks = false

#7.1 Ensure Virtual Machines are utilizing Managed Disks
managed_disks {
	count(d.vm_new) + count(d.vm_old) == count(d.vm_managed_new) + count(d.vm_managed_old)
}
deny[msg] {   
	vm_total = d.vm_new | d.vm_old 
	vm_managed = d.vm_managed_new | d.vm_managed_old                                                         
	vm_failed := vm_total - vm_managed
    count(vm_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'managed_disks' policy", [vm_failed])         
}