# Configure the Azure provider
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 2.65"
    }
  }
  required_version = ">= 0.14.9"
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# Create a resource group
resource "azurerm_resource_group" "rg" {
  name     = "mytfrgroup"
  location = "eastus"

  tags = {
    Environment = "staging"
    Team        = "DevOps"
  }
}

#1.21 Ensure that no custom subscription owner roles are created
data "azurerm_subscription" "primary" {
}

resource "azurerm_role_definition" "iamrole" {
  name        = "mytfcustomrole"
  scope       = data.azurerm_subscription.primary.id
  description = "This is a custom role created via Terraform"

  permissions {
    actions     = ["Microsoft.Resources/subscriptions/resourceGroups/read"]
    not_actions = []
  }

  assignable_scopes = [
    data.azurerm_subscription.primary.id,
  ]
}

#2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On'
resource "azurerm_security_center_auto_provisioning" "example" {
  auto_provision = "On"
}

#2.13 Ensure 'Additional email addresses' is configured with a security contact email
#2.14 Ensure that 'Notify about alerts with the following severity' is set to 'High'
#2.15 Ensure that 'All users with the following roles' is set to 'Owner'
resource "azurerm_security_center_contact" "example" {
  email = "contact@example.com"
  phone = "+1-555-555-5555"

  alert_notifications = true
  alerts_to_admins    = true
}

#3.1 Ensure that 'Secure transfer required' is set to 'Enabled'
#3.3 Ensure Storage logging is enabled for Queue service for read, write, and delete requests
#3.5 Ensure that 'Public access level' is set to Private for blob containers
#3.6 Ensure default network access rule for Storage Accounts is set to deny
#3.7 Ensure 'Trusted Microsoft Services' is enabled for Storage Account access
#3.8 Ensure soft delete is enabled for Azure Storage
resource "azurerm_storage_account" "sa" {
  name                      = "mytfsaccount"
  resource_group_name       = azurerm_resource_group.rg.name
  location                  = azurerm_resource_group.rg.location
  enable_https_traffic_only = true
  allow_blob_public_access  = false
  account_tier              = "Standard"
  account_replication_type  = "LRS"

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices", "Logging"]
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.sn.id]
  }

  queue_properties {
    logging {
      delete                = true
      read                  = true
      write                 = true
      version               = "1.0"
      retention_policy_days = 10
    }
  }
  blob_properties {
    delete_retention_policy {
      days = "30"
    }
  }

  tags = {
    environment = "staging"
  }
}

resource "azurerm_storage_container" "sc" {
  name                  = "mytfscontainer"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "private"
}

#4.1.1 Ensure that 'Auditing' is set to 'On'
#4.1.3 Ensure that 'Auditing' Retention is 'greater than 90 days'
#4.2.1 Ensure that Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled' (Automated)
resource "azurerm_sql_server" "sqlserver" {
  name                         = "mytfsqlserver"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "thisIsDog11"

  extended_auditing_policy {
    retention_in_days = 91
  }

  threat_detection_policy {
    state = "Enabled"
  }


  tags = {
    environment = "production"
  }
}

#4.3.1 Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server
resource "azurerm_postgresql_server" "psqlserver" {
  name                = "mytfpsqlserver"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  administrator_login          = "psqladmin"
  administrator_login_password = "H@Sh1CoR3!"

  sku_name   = "GP_Gen5_4"
  version    = "9.6"
  storage_mb = 640000

  backup_retention_days        = 7
  geo_redundant_backup_enabled = true
  auto_grow_enabled            = true

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}

#4.3.2 Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server 
resource "azurerm_mysql_server" "mysqlserver" {
  name                = "mytfmysqlserver"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  administrator_login          = "mysqladminun"
  administrator_login_password = "H@Sh1CoR3!"

  sku_name   = "B_Gen5_2"
  storage_mb = 5120
  version    = "5.7"

  auto_grow_enabled                 = true
  backup_retention_days             = 7
  geo_redundant_backup_enabled      = false
  infrastructure_encryption_enabled = false
  public_network_access_enabled     = true
  ssl_enforcement_enabled           = true
  ssl_minimal_tls_version_enforced  = "TLS1_2"
}

#4.3.3 Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server
#4.3.4 Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server
#4.3.5 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server
#4.3.6 Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server
#4.3.7 Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server
resource "azurerm_postgresql_configuration" "psqlconf1" {
  name                = "log_checkpoints"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_postgresql_server.psqlserver.name
  value               = "on"
}
resource "azurerm_postgresql_configuration" "psqlconf2" {
  name                = "log_connections"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_postgresql_server.psqlserver.name
  value               = "on"
}
resource "azurerm_postgresql_configuration" "psqlconf3" {
  name                = "log_disconnections"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_postgresql_server.psqlserver.name
  value               = "on"
}
resource "azurerm_postgresql_configuration" "psqlconf4" {
  name                = "connection_throttling"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_postgresql_server.psqlserver.name
  value               = "on"
}
resource "azurerm_postgresql_configuration" "psqlconf5" {
  name                = "log_retention_days"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_postgresql_server.psqlserver.name
  value               = 7
}

#4.3.8 Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled
resource "azurerm_postgresql_firewall_rule" "psqlfwr" {
  name                = "office"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_postgresql_server.psqlserver.name
  start_ip_address    = "1.2.3.4"
  end_ip_address      = "5.6.7.1"
}

#4.4 Ensure that Azure Active Directory Admin is configured
resource "azurerm_sql_active_directory_administrator" "example" {
  server_name         = azurerm_sql_server.sqlserver.name
  resource_group_name = azurerm_resource_group.rg.name
  login               = "sqladmin"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
}

# 5.2.1 Ensure that Activity Log Alert exists for Create Policy Assignment
#5.2.2 Ensure that Activity Log Alert exists for Delete Policy Assignment
#5.2.3 Ensure that Activity Log Alert exists for Create or Update Network Security Group
#5.2.4 Ensure that Activity Log Alert exists for Delete Network Security Group
#5.2.5 Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule
#5.2.6 Ensure that activity log alert exists for the Delete Network Security Group Rule
#5.2.7 Ensure that Activity Log Alert exists for Create or Update Security Solution
#5.2.8 Ensure that Activity Log Alert exists for Delete Security Solution
#5.2.9 Ensure that Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule
resource "azurerm_monitor_action_group" "main" {
  name                = "example-actiongroup"
  resource_group_name = azurerm_resource_group.rg.name
  short_name          = "p0action"

  webhook_receiver {
    name        = "callmyapi"
    service_uri = "http://example.com/alert"
  }
}

resource "azurerm_monitor_activity_log_alert" "main1" {
  name                = "example-activitylogalert1"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_resource_group.rg.id]
  description         = "Ensure that Activity Log Alert exists for Create Policy Assignment"

  criteria {
    resource_id    = azurerm_storage_account.sa.id
    operation_name = "Microsoft.Authorization/policyAssignments/write"
    category       = "Administrative"
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id

    webhook_properties = {
      from = "terraform"
    }
  }
}
resource "azurerm_monitor_activity_log_alert" "main2" {
  name                = "example-activitylogalert2"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_resource_group.rg.id]
  description         = "Ensure that Activity Log Alert exists for Delete Network Security Group"

  criteria {
    resource_id    = azurerm_storage_account.sa.id
    operation_name = "Microsoft.Network/networkSecurityGroups/delete"
    category       = "Administrative"
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id

    webhook_properties = {
      from = "terraform"
    }
  }
}
resource "azurerm_monitor_activity_log_alert" "main3" {
  name                = "example-activitylogalert3"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_resource_group.rg.id]
  description         = "Ensure that Activity Log Alert exists for Create or Update Security Solution"

  criteria {
    resource_id    = azurerm_storage_account.sa.id
    operation_name = "Microsoft.Security/securitySolutions/write"
    category       = "Security"
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id

    webhook_properties = {
      from = "terraform"
    }
  }
}
resource "azurerm_monitor_activity_log_alert" "main4" {
  name                = "example-activitylogalert4"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_resource_group.rg.id]
  description         = "Ensure that Activity Log Alert exists for Delete Policy Assignment"

  criteria {
    resource_id    = azurerm_storage_account.sa.id
    operation_name = "Microsoft.Authorization/policyAssignments/delete"
    category       = "Administrative"
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id

    webhook_properties = {
      from = "terraform"
    }
  }
}
resource "azurerm_monitor_activity_log_alert" "main5" {
  name                = "example-activitylogalert5"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_resource_group.rg.id]
  description         = "Ensure that Activity Log Alert exists for Create or Update Network Security Group"

  criteria {
    resource_id    = azurerm_storage_account.sa.id
    operation_name = "Microsoft.Network/networkSecurityGroups/write"
    category       = "Administrative"
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id

    webhook_properties = {
      from = "terraform"
    }
  }
}
resource "azurerm_monitor_activity_log_alert" "main6" {
  name                = "example-activitylogalert6"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_resource_group.rg.id]
  description         = "Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule"

  criteria {
    resource_id    = azurerm_storage_account.sa.id
    operation_name = "Microsoft.Network/networkSecurityGroups/securityRules/write"
    category       = "Administrative"
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id

    webhook_properties = {
      from = "terraform"
    }
  }
}
resource "azurerm_monitor_activity_log_alert" "main7" {
  name                = "example-activitylogalert7"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_resource_group.rg.id]
  description         = "Ensure that activity log alert exists for the Delete Network Security Group Rule"

  criteria {
    resource_id    = azurerm_storage_account.sa.id
    operation_name = "Microsoft.Network/networkSecurityGroups/securityRules/delete"
    category       = "Administrative"
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id

    webhook_properties = {
      from = "terraform"
    }
  }
}
resource "azurerm_monitor_activity_log_alert" "main8" {
  name                = "example-activitylogalert8"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_resource_group.rg.id]
  description         = "Ensure that Activity Log Alert exists for Delete Security Solution"

  criteria {
    resource_id    = azurerm_storage_account.sa.id
    operation_name = "Microsoft.Security/securitySolutions/delete"
    category       = "Security"
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id

    webhook_properties = {
      from = "terraform"
    }
  }
}
resource "azurerm_monitor_activity_log_alert" "main9" {
  name                = "example-activitylogalert9"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_resource_group.rg.id]
  description         = "Ensure that Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule"

  criteria {
    resource_id    = azurerm_storage_account.sa.id
    operation_name = "Microsoft.Sql/servers/firewallRules/write"
    category       = "Administrative"
  }

  action {
    action_group_id = azurerm_monitor_action_group.main.id

    webhook_properties = {
      from = "terraform"
    }
  }
}

#6.1 Ensure that RDP access is restricted from the internet
#6.2 Ensure that SSH access is restricted from the internet
#6.6 Ensure that UDP Services are restricted from the Internet
resource "azurerm_network_security_group" "nsg" {
  name                = "mytfnsgroup"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name


  tags = {
    environment = "staging"
  }
}

resource "azurerm_network_security_rule" "nsr" {
  for_each                    = local.nsgrules
  name                        = each.value.name
  direction                   = each.value.direction
  access                      = each.value.access
  priority                    = each.value.priority
  protocol                    = each.value.protocol
  source_port_range           = each.value.source_port_range
  destination_port_range      = each.value.destination_port_range
  source_address_prefix       = each.value.source_address_prefix
  destination_address_prefix  = each.value.destination_address_prefix
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}

#6.3 Ensure no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)
resource "azurerm_sql_firewall_rule" "sqlfwrule" {
  name                = "mytfsqlfwrule"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_sql_server.sqlserver.name
  start_ip_address    = "1.2.3.4"
  end_ip_address      = "4.5.6.7"
}

#6.4 Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'
resource "azurerm_network_watcher_flow_log" "nwwatcherflow" {
  network_watcher_name = azurerm_network_watcher.nwwatcher.name
  resource_group_name  = azurerm_resource_group.rg.name

  network_security_group_id = azurerm_network_security_group.nsg.id
  storage_account_id        = azurerm_storage_account.sa.id
  enabled                   = true

  retention_policy {
    enabled = true
    days    = 91
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.test.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.test.location
    workspace_resource_id = azurerm_log_analytics_workspace.test.id
    interval_in_minutes   = 10
  }
}


resource "azurerm_network_watcher" "nwwatcher" {
  name                = "mynwwatcher"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}
resource "azurerm_log_analytics_workspace" "test" {
  name                = "acctestlaw"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
}

# 7.1 Ensure Virtual Machines are utilizing Managed Disks
resource "azurerm_linux_virtual_machine" "vm" {
  name                            = "mytfvmlinux"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  size                            = "Standard_F2"
  admin_username                  = "ubaidilyas"
  admin_password                  = "Ub@!d!lyas99"
  disable_password_authentication = false
  network_interface_ids = [
    azurerm_network_interface.nic.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "16.04-LTS"
    version   = "latest"
  }
}

resource "azurerm_network_interface" "nic" {
  name                = "mytfnic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.sn.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_subnet" "sn" {
  name                 = "mytfsnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.2.0/24"]
  service_endpoints    = ["Microsoft.Sql", "Microsoft.Storage"]
}

resource "azurerm_virtual_network" "vnet" {
  name                = "mytfvnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_virtual_machine" "main" {
  name                  = "mytfvm"
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.main.id]
  vm_size               = "Standard_DS1_v2"

  # Uncomment this line to delete the OS disk automatically when deleting the VM
  # delete_os_disk_on_termination = true

  # Uncomment this line to delete the data disks automatically when deleting the VM
  # delete_data_disks_on_termination = true

  storage_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "16.04-LTS"
    version   = "latest"
  }
  storage_os_disk {
    name              = "myosdisk1"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"
  }
  os_profile {
    computer_name  = "hostname"
    admin_username = "testadmin"
    admin_password = "Password1234!"
  }
  os_profile_linux_config {
    disable_password_authentication = false
  }
  tags = {
    environment = "staging"
  }
}

resource "azurerm_virtual_network" "main" {
  name                = "network"
  address_space       = ["10.9.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "internal" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_interface" "main" {
  name                = "nicnic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "testconfiguration1"
    subnet_id                     = azurerm_subnet.internal.id
    private_ip_address_allocation = "Dynamic"
  }
}

# 8.1 Ensure that the expiration date is set on all keys
# 8.2 Ensure that the expiration date is set on all Secrets
# 8.4 Ensure the key vault is recoverable
data "azurerm_client_config" "current" {}


resource "azurerm_key_vault" "kv" {
  name                        = "mytfkv"
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true


  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get",
    ]

    secret_permissions = [
      "Get",
    ]

    storage_permissions = [
      "Get",
    ]
  }
}

resource "azurerm_key_vault_key" "good_example" {
  name            = "generated-certificate"
  key_vault_id    = azurerm_key_vault.kv.id
  key_type        = "RSA"
  key_size        = 2048
  expiration_date = "1982-12-31T00:00:00Z"

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}

resource "azurerm_key_vault_secret" "good_example" {
  name         = "secret-sauce"
  value        = "szechuan"
  key_vault_id = azurerm_key_vault.kv.id
  expiration_date = "1982-12-31T00:00:00Z"

}

# 8.5 Enable role-based access control (RBAC) within Azure Kubernetes Services
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "mytfaks"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "exampleaks1"

  role_based_access_control {
    enabled = true
  }

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Production"
  }
}

#9.1 Ensure App Service Authentication is set on Azure App Service
#9.2 Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service
#9.3 Ensure web app is using the latest version of TLS encryption
#9.4 Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'
#9.5 Ensure that Register with Azure Active Directory is enabled on App Service
#9.6 Ensure that 'PHP version' is the latest, if used to run the web app
#9.7 Ensure that 'Python version' is the latest, if used to run the web app
#9.8 Ensure that 'Java version' is the latest, if used to run the web app
#9.9 Ensure that 'HTTP Version' is the latest, if used to run the web app
#9.10 Ensure FTP deployments are disabled
resource "azurerm_app_service_plan" "appserviceplan" {
  name                = "mytfappserviceplan"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  sku {
    tier = "Standard"
    size = "S1"
  }
}

resource "azurerm_app_service" "appservice" {
  name                = "mytfappservice"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  app_service_plan_id = azurerm_app_service_plan.appserviceplan.id
  https_only          = true
  client_cert_enabled = true

  auth_settings {
    enabled = true
  }

  identity {
    type = "UserAssigned"
  }

  site_config {
    min_tls_version          = "1.2"
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    php_version              = "7.4"
    python_version           = "3.4"
    java_version             = "1.8"
    java_container           = "TOMCAT"
    java_container_version   = "1.0"
      http2_enabled = true
      ftps_state = "FtpsOnly"

  }

  app_settings = {
    "SOME_KEY" = "some-value"
  }

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }
}