package azure.vm.data

#List of all vms
vm_new := { vm |
	resource := input.resource_changes[i]
	regex.match(`^azurerm_[lw][a-z]*_virtual` , resource.type)
	vm := resource.change.after.name
} 

vm_old := { vm |
	resource := input.resource_changes[i]
	resource.type == "azurerm_virtual_machine"
	vm := resource.change.after.name
} 

#7.1 Ensure Virtual Machines are utilizing Managed Disks
vm_managed_new := { vm |
	resource := input.resource_changes[i]
	regex.match(`^azurerm_[lw][a-z]*_virtual` , resource.type)
	resource.change.after != null
    vm := resource.change.after.name
} 
vm_managed_old := { vm |
	resource := input.resource_changes[i]
	resource.type == "azurerm_virtual_machine"
	resource.change.after.storage_os_disk[_].managed_disk_type != null
    vm := resource.change.after.name
} 