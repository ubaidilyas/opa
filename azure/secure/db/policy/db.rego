package azure.secure.db

import data.azure.db.data as d

#default sql_audit = false
#default sql_audit_retention = false
#default sql_advanced_threat_protection = false
#default postgresql_ssl = false
#default mysqlssl = false
#default psql_log_checkpoints = false
#default psql_log_conections = false
#default psql_log_disconnections = false
#default psql_connection_throttling = false
#default log_retention_days = false
#default psql_firewall_rule = false
#default sql_server_aad = false

count_total_sql := count(d.db_total_sql)
count_total_psql := count(d.db_total_psql)
count_total_mysql := count(d.db_total_mysql)
 
#4.1.1 Ensure that 'Auditing' is set to 'On' (Automated)
sql_audit {
	count_total_sql != 0
	count_total_sql == count(d.db_audit_sql)
}
deny[msg] {     
	db_failed := d.db_total_sql - d.db_audit_sql
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'audit_sql' policiy", [db_failed])         
}

#4.1.3 Ensure that 'Auditing' Retention is 'greater than 90 days'
sql_audit_retention {
	count_total_sql != 0
	count_total_sql == count(d.db_audit_retention_sql)
}
deny[msg] {     
	db_failed := d.db_total_sql - d.db_audit_retention_sql
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'audit_retention_sql' policiy", [db_failed])         
}

#4.2.1 Ensure that Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled' (Automated)
sql_advanced_threat_protection{
	count_total_sql != 0
	count_total_sql == count(d.db_atp_sql)
}
deny[msg] {     
	db_failed := d.db_total_sql - d.db_atp_sql
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'sql_advanced_threat_protection' policiy", [db_failed])         
}

#4.3.1 Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server
postgresql_ssl{
	count_total_psql != 0
	count_total_psql == count(d.db_psqlssl)
}
deny[msg] {     
	db_failed := d.db_total_psql - d.db_psqlssl
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'postgresql_ssl' policiy", [db_failed])         
}

#4.3.2 Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server 
mysqlssl{
	count_total_mysql != 0
	count_total_mysql== count(d.db_mysqlssl)
}
deny[msg] {     
	db_failed := d.db_total_mysql - d.db_mysqlssl
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'mysqlssl' policiy", [db_failed])         
}

#4.3.3 Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server
log_checkpoints{
	count_total_psql != 0
	count_total_psql == count(d.db_plogcheck)
}
deny[msg] {     
	db_failed := d.db_total_psql - d.db_plogcheck
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'log_checkpoints' policiy", [db_failed])         
}

#4.3.4 Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server
psql_log_conections{
	count_total_psql != 0
	count_total_psql == count(d.db_plogconnect)
}
deny[msg] {     
	db_failed := d.db_total_psql - d.db_plogcoonect
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'log_conections' policiy", [db_failed])         
}

#4.3.5 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server
psql_log_disconnections{
	count_total_psql != 0
	count_total_psql== count(d.db_plogdisconnect)

}
deny[msg] {     
	db_failed := d.db_total_psql - d.db_plogdisconnect
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'log_disconnections' policiy", [db_failed])         
}

#4.3.6 Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server
psql_connection_throttling {
	count_total_psql != 0
	count_total_psql== count(d.db_plogthrottle)

}
deny[msg] {     
	db_failed := d.db_total_psql - d.db_plogthrottle
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'connection_throttling' policiy", [db_failed])         
}

#4.3.7 Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server
psql_log_retention_days {
	count_total_psql != 0
	count_total_psql == count(d.db_plogretention)

}
deny[msg] {     
	db_failed := d.db_total_psql - d.db_plogretention
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'log_retention_days' policiy", [db_failed])         
}

#4.3.8 Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled
psql_firewall_rule {
	count_total_psql != 0
	count_total_psql == count_total_psql - count(d.db_psqlfwr)
}
deny[msg] {     
	db_failed := d.db_total_psql & d.db_psqlfwr
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'psql_firewall_rule' policiy", [db_failed])         
}

#4.4 Ensure that Azure Active Directory Admin is configured
sql_server_aad {
	count_total_sql != 0
	count_total_sql == count(d.db_sqlad)
}
deny[msg] {     
	db_failed := d.db_total_sql - d.db_sqlad
    count(db_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'sql_aad' policiy", [db_failed])         
}