package azure.vmlinux.data

import data.exceptions as ex

#List of all vms
vm_total := { vm |
	resource := input.resource_changes[i]
	resource.type == "azurerm_linux_virtual_machine"
	vm := resource.change.after.name
} 

#List of all vms that pass name
vm_name := { vm |
	resource := input.resource_changes[i]
	resource.type == "azurerm_linux_virtual_machine"
	startswith(resource.change.after.name, "mytf")
	vm := resource.change.after.name
} 

#List of default vms that pass name
vm_default := { vm | resource := input.resource_changes[i]
	resource.type == "azurerm_linux_virtual_machine"
	startswith(resource.change.after.name, "mytf")
	resource.change.after.size == "Standard_F2" 
	vm := resource.change.after.name
}

#List of all vms that pass name
vm_exception := { vm | resource := input.resource_changes[i]
	resource.type == "azurerm_linux_virtual_machine"
	resource.change.after.name == ex.developer[j].name
	resource.change.after.size == ex.developer[j].size
	vm := resource.change.after.name
}

#List of all vms that have latest version
vm_version := { vm |
	resource := input.resource_changes[i]
	resource.type == "azurerm_linux_virtual_machine"
    resource.change.after.source_image_reference[_].version == "latest"
    vm := resource.change.after.name
} 

#List of all vms that have manged disk
vm_managed := { vm |
	resource := input.resource_changes[i]
	resource.type == "azurerm_linux_virtual_machine"
	resource.change.after != null
    vm := resource.change.after.name

} 