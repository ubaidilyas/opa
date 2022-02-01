package azure.secure.appservice

import data.azure.appservice.data as d

#default sapp_authentication = false
#default web_app_https_only = false
#default web_app_tls_version = false
#default web_app_client_cert_enabled = false
#default web_app_aad_enabled = false
#default web_app_php_version = false
#default web_app_python_version = false
#default web_app_java_version = false
#default web_app_http_version = false
#default web_app_ftp_disable = false

count_total := count(d.sapp_total)

#9.1 Ensure App Service Authentication is set on Azure App Service
sapp_authentication {
	count_total != 0
	count_total == count(d.sapp_auth) + count(d.sapp_auth_ex)
}
deny[msg] {      
	sapp_auth_total = d.sapp_auth | d.sapp_auth_ex                                                     
	sapp_failed := d.sapp_total - sapp_auth_total
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'sapp_authentication' policy", [sapp_failed])         
}

#9.2 Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service
web_app_https_only {
	count_total != 0
	count_total == count(d.web_app_https)
}
deny[msg] {                                                                 
	sapp_failed := d.sapp_total - d.web_app_https
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'web_app_https_only' policy", [sapp_failed])         
}

#9.3 Ensure web app is using the latest version of TLS encryption (Automated)
web_app_tls_version {
	count_total != 0
	count_total == count(d.web_app_latest_tls) + count(d.web_app_latest_default)
}
deny[msg] {         
	sapp_tls_total = d.web_app_latest_tls | d.web_app_latest_default                                                
	sapp_failed := d.sapp_total - sapp_tls_total
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'web_app_tls_version' policy", [sapp_failed])         
}

#9.4 Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'
web_app_client_cert_enabled {
	count_total != 0
	count_total == count(d.web_app_client_cert)
}
deny[msg] {                                                                 
	sapp_failed := d.sapp_total - d.web_app_client_cert
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'web_app_client_cert_enabled' policy", [sapp_failed])         
}

#9.5 Ensure that Register with Azure Active Directory is enabled on App Service
web_app_aad_enabled {
	count_total != 0
	count_total == count(d.web_app_aad)
}
deny[msg] {                                                                 
	sapp_failed := d.sapp_total - d.web_app_aad
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'web_app_aad_enabled' policy", [sapp_failed])         
}

#9.6 Ensure that 'PHP version' is the latest, if used to run the web app
web_app_php_version {
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.site_config[_].php_version != null
	count_total != 0
	count_total == count(d.web_app_latest_php)
}
deny[msg] {
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.site_config[_].php_version != null                                                                 
	sapp_failed := d.sapp_total - d.web_app_latest_php
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'web_app_php_version' policy", [sapp_failed])         
}

#9.7 Ensure that 'Python version' is the latest, if used to run the web app
web_app_python_version {
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.site_config[_].python_version != null
	count_total != 0
	count_total == count(d.web_app_latest_python)
}
deny[msg] {
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.site_config[_].python_version != null                                                                 
	sapp_failed := d.sapp_total - d.web_app_latest_python
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'web_app_python_version' policy", [sapp_failed])         
}

#9.8 Ensure that 'Java version' is the latest, if used to run the web app
web_app_java_version {
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.site_config[_].java_version != null
	count_total != 0
	count_total == count(d.web_app_latest_java)
}
deny[msg] {  
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.site_config[_].java_version != null                                                               
	sapp_failed := d.sapp_total - d.web_app_latest_java
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'web_app_java_version' policy", [sapp_failed])         
}

#9.9 Ensure that 'HTTP Version' is the latest, if used to run the web app
web_app_http_version {
	count_total != 0
	count_total == count(d.web_app_latest_http)
}
deny[msg] {                                                              
	sapp_failed := d.sapp_total - d.web_app_latest_http
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'web_app_http_version' policy", [sapp_failed])         
}

#9.10 Ensure FTP deployments are disabled
web_app_ftp_disable {
	count_total != 0
	count_total == count(d.web_app_ftp)
}
deny[msg] {                                                                 
	sapp_failed := d.sapp_total - d.web_app_ftp
    count(sapp_failed) != 0
	msg := sprintf("'%v'failed to pass pre-defined 'web_app_ftp_disable' policy", [sapp_failed])         
}