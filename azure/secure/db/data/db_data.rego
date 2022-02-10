package azure.db.data


#List of sql db servers
db_total_sql := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_sql_server"
	resource.change.actions[_] != "delete"
	db := resource.change.after.name
} 
#List of postgresql db servers
db_total_psql := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_postgresql_server"
	resource.change.actions[_] != "delete"
	db := resource.change.after.name
} 
#List of postgresql db servers
db_total_mysql := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_mysql_server"
	resource.change.actions[_] != "delete"
	db := resource.change.after.name
} 

#4.1.1 Ensure that 'Auditing' is set to 'On' (Automated)
db_audit_sql := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_sql_server"
	resource.change.after.extended_auditing_policy
	db := resource.change.after.name
}

#4.1.3 Ensure that 'Auditing' Retention is 'greater than 90 days'
db_audit_retention_sql := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_sql_server"
	to_number(resource.change.after.extended_auditing_policy[_].retention_in_days) >= 90
	db := resource.change.after.name
}

#4.2.1 Ensure that Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled'
db_atp_sql := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_sql_server"
	lower(resource.change.after.threat_detection_policy[_].state) == "enabled"
	db := resource.change.after.name
} 

#4.3.1 Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server
db_psqlssl := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_postgresql_server"
	resource.change.after.ssl_enforcement_enabled == true
	db := resource.change.after.name
} 

#4.3.2 Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server 
db_mysqlssl := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_mysql_server"
	resource.change.after.ssl_enforcement_enabled == true
	db := resource.change.after.name
} 

#4.3.3 Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server
db_plogcheck := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_postgresql_configuration"
	lower(resource.change.after.name) == "log_checkpoints"
	lower(resource.change.after.value) == "on"
	db := resource.change.after.server_name
} 

#4.3.4 Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server
db_plogconnect := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_postgresql_configuration"
	lower(resource.change.after.name) == "log_connections"
	lower(resource.change.after.value) == "on"
	db := resource.change.after.server_name
} 

#4.3.5 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server
db_plogdisconnect := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_postgresql_configuration"
	lower(resource.change.after.name) == "log_disconnections"
	lower(resource.change.after.value) == "on"
	db := resource.change.after.server_name
} 

#4.3.6 Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server
db_plogthrottle := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_postgresql_configuration"
	lower(resource.change.after.name) == "connection_throttling"
	lower(resource.change.after.value) == "on"
	db := resource.change.after.server_name
} 

#4.3.7 Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server
db_plogretention := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_postgresql_configuration"
	resource.change.after.name == "log_retention_days"
	to_number(resource.change.after.value) > 3
	db := resource.change.after.server_name
} 

#4.3.8 Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled
db_psqlfwr := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_postgresql_firewall_rule"
	resource.change.after.end_ip_address == "0.0.0.0"
	resource.change.after.start_ip_address == "0.0.0.0"
	db := resource.change.after.server_name
} 

#4.4 Ensure that Azure Active Directory Admin is configured
db_sqlad := { db |
	resource := input.resource_changes[i]
	resource.type == "azurerm_sql_active_directory_administrator"
	db := resource.change.after.server_name
} 

#db_va_sap:= { db |
#	resource := input.resource_changes[i]
#	resource.type == "azurerm_mssql_server_security_alert_policy"
#	resource.change.after.state == "Enabled"
#	db := resource.change.after.server_name
#
#} 

#db_va_sva:= { db |
#	resource := input.resource_changes[i]
#	resource.type == "azurerm_mssql_server_vulnerability_assessment"
#	resource.change.after.state == "Enabled"
#	db := resource.change.after.server_name
#
#} 

