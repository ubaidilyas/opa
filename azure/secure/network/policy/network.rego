package azure.secure.network

import data.azure.network.data as d

default standard_name = false
default rdp_disable = false
default ssh_disable = false
default udp_disable = false

#Checking standard name
standard_name {
	count(d.nw_total_sg) == count(d.nw_name_sg)
}
deny[msg] {                                                                 
	nw_failed := d.nw_total_sg - d.nw_name_sg
    count(nw_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'standard_name' policy", [nw_failed])         
}

#Checking that RDP is disabled on all NSG
rdp_disable {
	count(d.nw_total_sg) == count(d.nw_rdp_disable)

}
deny[msg] {     
	nw_failed := d.nw_total_sg - d.nw_rdp_disable
    count(nw_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'rdp_disable' policiy", [nw_failed])         
}

#Checking that SSH is disabled on all NSG
ssh_disable {
	count(d.nw_total_sg) == count(d.nw_ssh_disable)

}
deny[msg] {     
	nw_failed := d.nw_total_sg - d.nw_ssh_disable
    count(nw_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'ssh_disable' policiy", [nw_failed])         
}

#Checking that UDP is disabled on all NSG
udp_disable {
	count(d.nw_total_sg) == count(d.nw_udp_disable)

}
deny[msg] {     
	nw_failed := d.nw_total_sg - d.nw_udp_disable
    count(nw_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'udp_disable' policiy", [nw_failed])         
}