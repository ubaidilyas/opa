package azure.secure.network

import data.azure.network.data as d

#default rdp_disable = false
#default ssh_disable = false
#default sql_firewall_rule = false
#default flow_log_retention = false
#default udp_disable = false

count_total_nw_sec_group := count(d.nw_total_sg)
count_total_sql := count(d.db_total_sql)
count_total_nw_watcher := count(d.nw_total_watcher)

#6.1 Ensure that RDP access is restricted from the internet
rdp_disable {
	count_total_nw_sec_group != 0
	count_total_nw_sec_group == count_total_nw_sec_group - (count(d.nw_rdp_enable_nsr) + count(d.nw_rdp_enable_nsg))
} 
deny[msg] {     
	nw_failed := d.nw_total_sg & ( d.nw_rdp_enable_nsr | d.nw_rdp_enable_nsg )
    count(nw_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'rdp_disable' policiy", [nw_failed])         
}
#6.2 Ensure that SSH access is restricted from the internet
ssh_disable {
	count_total_nw_sec_group != 0
	count_total_nw_sec_group == count_total_nw_sec_group - ( count(d.nw_ssh_enable_nsr) + count(d.nw_ssh_enable_nsg) )
}
deny[msg] {     
	nw_failed := d.nw_total_sg & ( d.nw_ssh_enable_nsr | d.nw_ssh_enable_nsg )
    count(nw_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'ssh_disable' policiy", [nw_failed])         
}

#6.3 Ensure no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)
sql_firewall_rule {
	count_total_sql != 0
	count_total_sql == count_total_sql - count(d.db_sqlfwr)
}
deny[msg] {     
	db_failed := d.db_total_sql & d.db_sqlfwr
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'sql_firewall_rule' policiy", [db_failed])         
}

#6.4 Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'
flow_log_retention {
	count_total_nw_watcher != 0
	count_total_nw_watcher == count(d.nw_flow_log)
}
deny[msg] {     
	nw_failed := d.nw_total_watcher - d.nw_flow_log
    count(nw_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'flow_log_retention' policiy", [nw_failed])         
}

#6.6 Ensure that UDP Services are restricted from the Internet
udp_disable {
	count_total_nw_sec_group != 0
	count_total_nw_sec_group == count_total_nw_sec_group - ( count(d.nw_udp_enable_nsr) + count(d.nw_udp_enable_nsg) )
}
deny[msg] {     
	nw_failed := d.nw_total_sg & ( d.nw_udp_enable_nsr | d.nw_udp_enable_nsg )
    count(nw_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'udp_disable' policiy", [nw_failed])         
}
