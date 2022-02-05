package azure.appservice.data

import data.exceptions as ex

#List of all app service
sapp_total := { sa |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.actions[_] != "delete"
	sa := resource.change.after.name
} 
#9.1 Ensure App Service Authentication is set on Azure App Service
sapp_auth := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.auth_settings[_].enabled=true
    app := resource.change.after.name
} 
# Exception is required as it is undesirable for marketing and support websites
sapp_auth_ex := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.name == ex.websites[j].name
    app := resource.change.after.name
} 

#9.2 Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service
web_app_https := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.https_only=true
    app := resource.change.after.name
} 

#9.3 Ensure web app is using the latest version of TLS encryption (Automated)
web_app_latest_tls := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	to_number(resource.change.after.site_config[_].min_tls_version) == 1.2
	app := resource.change.after.name
} 

# TLS version by default is 1.2
web_app_latest_default := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	config:= resource.change.after.site_config[_]
	not config.min_tls_version
	app := resource.change.after.name
} 
#9.4 Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'
web_app_client_cert := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.client_cert_enabled == true
	app := resource.change.after.name
} 
#9.5 Ensure that Register with Azure Active Directory is enabled on App Service
web_app_aad := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.identity[_].type == "UserAssigned"
	app := resource.change.after.name
} 
#9.6 Ensure that 'PHP version' is the latest, if used to run the web app
web_app_latest_php := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	to_number(resource.change.after.site_config[_].php_version) == 7.4
	app := resource.change.after.name
} 
#9.7 Ensure that 'Python version' is the latest, if used to run the web app
web_app_latest_python := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	to_number(resource.change.after.site_config[_].python_version) == 3.4
	app := resource.change.after.name
} 
#9.8 Ensure that 'Java version' is the latest, if used to run the web app
web_app_latest_java := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	to_number(resource.change.after.site_config[_].java_version) == 1.8
	app := resource.change.after.name
} 
#9.9 Ensure that 'HTTP Version' is the latest, if used to run the web app
web_app_latest_http := { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	resource.change.after.site_config[_].http2_enabled == true
	app := resource.change.after.name
} 
#9.10 Ensure FTP deployments are disabled
web_app_ftp:= { app |
	resource := input.resource_changes[i]
	resource.type == "azurerm_app_service"
	allowed :=["FtpsOnly" , "Disabled"]
	resource.change.after.site_config[_].ftps_state == allowed[_]
	app := resource.change.after.name
} 
