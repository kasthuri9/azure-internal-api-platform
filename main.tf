data "azurerm_client_config" "current" {}

# =============================================================================
# Resource Group
# =============================================================================
resource "azurerm_resource_group" "main" {
  name     = "${local.prefix}-rg"
  location = var.location
  tags     = local.common_tags
}

# =============================================================================
# Networking — VNet with two subnets
#
# =============================================================================

resource "azurerm_virtual_network" "main" {
  name                = "${local.prefix}-vnet"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.0.0.0/16"]
  tags                = local.common_tags
}

resource "azurerm_subnet" "functions" {
  name                 = "${local.prefix}-snet-functions"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
  service_endpoints    = ["Microsoft.Storage", "Microsoft.KeyVault"]

  delegation {
    name = "functions-delegation"
    service_delegation {
      name    = "Microsoft.Web/serverFarms"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "${local.prefix}-snet-private-endpoints"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]

  # Required — Azure won't honour private endpoint NIC policies otherwise
  private_endpoint_network_policies_enabled = false
}

# =============================================================================
# Network Security Groups
#
# Functions NSG: allow outbound HTTPS to Azure services; deny internet inbound.
# Private endpoints NSG: allow only VNet-internal traffic inbound.
#
# NOTE: NSGs on private endpoint subnets don't filter traffic to the endpoint
# itself (Azure bypasses them for PE traffic), but they're good practice and
# required by some compliance frameworks.
# =============================================================================
resource "azurerm_network_security_group" "functions" {
  name                = "${local.prefix}-nsg-functions"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags

  security_rule {
    name                       = "allow-https-outbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "AzureCloud"
  }

  security_rule {
    name                       = "deny-internet-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "functions" {
  subnet_id                 = azurerm_subnet.functions.id
  network_security_group_id = azurerm_network_security_group.functions.id
}

resource "azurerm_network_security_group" "private_endpoints" {
  name                = "${local.prefix}-nsg-private-endpoints"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags

  security_rule {
    name                       = "allow-vnet-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "VirtualNetwork"
  }

  security_rule {
    name                       = "deny-internet-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "private_endpoints" {
  subnet_id                 = azurerm_subnet.private_endpoints.id
  network_security_group_id = azurerm_network_security_group.private_endpoints.id
}

# =============================================================================
# Key Vault
#
# Stores the CA certificate and client certificate generated below.
# Network ACLs deny all public traffic; only the functions subnet (via service
# endpoint) can reach it. In production, a private endpoint would replace the
# service endpoint — see README for the full private endpoint pattern.
# =============================================================================
resource "azurerm_key_vault" "main" {
  name                       = "${local.prefix}-kv"
  location                   = var.location
  resource_group_name        = azurerm_resource_group.main.name
  sku_name                   = "standard"
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days = 7
  purge_protection_enabled   = true

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    # Service endpoint: functions subnet can reach Key Vault directly
    virtual_network_subnet_ids = [azurerm_subnet.functions.id]
  }

  tags = local.common_tags
}

# Terraform deployer needs access to write the certificates
resource "azurerm_key_vault_access_policy" "deployer" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions      = ["Get", "List", "Set", "Delete", "Recover", "Purge"]
  certificate_permissions = ["Get", "List", "Import", "Delete", "Recover", "Purge"]
}

# Function App managed identity — read-only access to secrets
resource "azurerm_key_vault_access_policy" "function_app" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_linux_function_app.main.identity[0].principal_id

  secret_permissions = ["Get", "List"]
}

# =============================================================================
# Certificates — CA + client certificate
#
# The tls provider generates a self-signed CA, then signs a client certificate
# with it. Both are stored in Key Vault.
#
# IMPORTANT CAVEAT: The tls provider stores private keys in Terraform state.
# State must be encrypted and access-controlled (Azure Blob with RBAC).
# In production, use Key Vault-native certificate generation so the private key
# never exists outside the HSM. This is acceptable for this assessment.
# =============================================================================
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem   = tls_private_key.ca.private_key_pem
  is_ca_certificate = true

  subject {
    common_name  = "${local.prefix} Internal CA"
    organization = "Checkout.com Platform"
    country      = "GB"
  }

  validity_period_hours = 8760 # 1 year
  set_subject_key_id    = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
  ]
}

resource "tls_private_key" "client" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "client" {
  private_key_pem = tls_private_key.client.private_key_pem

  subject {
    common_name  = "${local.prefix}-mtls-client"
    organization = "Checkout.com Platform"
    country      = "GB"
  }
}

resource "tls_locally_signed_cert" "client" {
  cert_request_pem   = tls_cert_request.client.cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 4380 # 6 months
  set_subject_key_id    = true

  allowed_uses = [
    "client_auth",
    "digital_signature",
  ]
}

# Store in Key Vault — deployer access policy must exist first
resource "azurerm_key_vault_secret" "ca_cert" {
  name         = "ca-cert"
  value        = tls_self_signed_cert.ca.cert_pem
  key_vault_id = azurerm_key_vault.main.id
  content_type = "application/x-pem-file"
  depends_on   = [azurerm_key_vault_access_policy.deployer]
}

resource "azurerm_key_vault_secret" "client_cert" {
  name         = "client-cert"
  value        = tls_locally_signed_cert.client.cert_pem
  key_vault_id = azurerm_key_vault.main.id
  content_type = "application/x-pem-file"
  depends_on   = [azurerm_key_vault_access_policy.deployer]
}

resource "azurerm_key_vault_secret" "client_key" {
  name         = "client-key"
  value        = tls_private_key.client.private_key_pem
  key_vault_id = azurerm_key_vault.main.id
  content_type = "application/x-pem-file"
  depends_on   = [azurerm_key_vault_access_policy.deployer]
}

# =============================================================================
# Observability — Log Analytics Workspace + Application Insights
#
# App Insights is deployed in workspace mode (backed by Log Analytics) so all
# telemetry — function traces, exceptions, request logs — flows into one place
# and can be queried together with a single KQL query.
# =============================================================================
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${local.prefix}-law"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.common_tags
}

resource "azurerm_application_insights" "main" {
  name                = "${local.prefix}-ai"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  tags                = local.common_tags
}

# =============================================================================
# Storage Account — required by the Function App runtime
#
# Public access is disabled; only the functions subnet can reach it via service
# endpoint. In production this would use a private endpoint instead.
# =============================================================================
resource "azurerm_storage_account" "main" {
  name                            = local.storage_account_name
  resource_group_name             = azurerm_resource_group.main.name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  public_network_access_enabled   = false
  allow_nested_items_to_be_public = false

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [azurerm_subnet.functions.id]
  }

  tags = local.common_tags
}

# =============================================================================
# App Service Plan — Elastic Premium
#
# The Consumption plan does NOT support VNet integration, so Elastic Premium
# (EP1) is the minimum viable SKU for a privately-networked function.
# =============================================================================
resource "azurerm_service_plan" "main" {
  name                = "${local.prefix}-asp"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"
  sku_name            = "EP1"
  tags                = local.common_tags
}

# =============================================================================
# Function App
#
# Key settings:
#   public_network_access_enabled = false  — no direct internet access
#   virtual_network_subnet_id              — VNet integration via functions subnet
#   vnet_route_all_enabled = true          — all outbound goes via VNet
#   identity SystemAssigned                — managed identity, no passwords
#   ip_restriction                         — only accepts inbound from VNet
# =============================================================================
resource "azurerm_linux_function_app" "main" {
  name                          = "${local.prefix}-func"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.main.name
  service_plan_id               = azurerm_service_plan.main.id
  storage_account_name          = azurerm_storage_account.main.name
  storage_account_access_key    = azurerm_storage_account.main.primary_access_key
  public_network_access_enabled = false
  virtual_network_subnet_id     = azurerm_subnet.functions.id

  identity {
    type = "SystemAssigned"
  }

  site_config {
    vnet_route_all_enabled = true
    ftps_state             = "Disabled"
    http2_enabled          = true
    minimum_tls_version    = "1.2"

    application_stack {
      python_version = "3.11"
    }

    # Only accept inbound from within the VNet
    ip_restriction {
      virtual_network_subnet_id = azurerm_subnet.functions.id
      action                    = "Allow"
      priority                  = 100
      name                      = "allow-vnet-inbound"
    }

    ip_restriction_default_action = "Deny"
  }

  app_settings = {
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.main.connection_string
    APPINSIGHTS_INSTRUMENTATIONKEY        = azurerm_application_insights.main.instrumentation_key
    FUNCTIONS_EXTENSION_VERSION           = "~4"
    FUNCTIONS_WORKER_RUNTIME              = "python"
    KEY_VAULT_URI                         = azurerm_key_vault.main.vault_uri
    # mTLS: the CA cert URI is passed in so the app can retrieve it if needed
    CA_CERT_SECRET_URI                    = azurerm_key_vault_secret.ca_cert.id
    WEBSITE_VNET_ROUTE_ALL                = "1"
    WEBSITE_CONTENTOVERVNET               = "1"
  }

  tags = local.common_tags

  depends_on = [azurerm_key_vault_access_policy.deployer]
}

# =============================================================================
# Private Endpoint — Function App
#
# Makes the function reachable via a private IP inside the VNet. Combined with
# public_network_access_enabled = false, this means no internet path exists.
# APIM (or any internal caller) reaches the function via this private IP.
# =============================================================================
resource "azurerm_private_endpoint" "function_app" {
  name                = "${local.prefix}-func-pe"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  tags                = local.common_tags

  private_service_connection {
    name                           = "${local.prefix}-func-pe-conn"
    private_connection_resource_id = azurerm_linux_function_app.main.id
    subresource_names              = ["sites"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "func-dns-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.function_app.id]
  }
}

resource "azurerm_private_dns_zone" "function_app" {
  name                = "privatelink.azurewebsites.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "function_app" {
  name                  = "func-dns-vnet-link"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.function_app.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
  tags                  = local.common_tags
}

# =============================================================================
# Alert Rule — HTTP 5xx errors on the Function App
#
# Fires if the function returns more than 10 server errors in a 15-minute
# window. Notifications go to the platform email via the action group.
# =============================================================================
resource "azurerm_monitor_action_group" "platform" {
  name                = "${local.prefix}-ag"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "cko-platform"
  tags                = local.common_tags

  email_receiver {
    name                    = "platform-team"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }
}

resource "azurerm_monitor_metric_alert" "function_5xx" {
  name                = "${local.prefix}-alert-func-5xx"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_linux_function_app.main.id]
  description         = "Fires when the Function App returns more than 10 HTTP 5xx errors in 15 minutes"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  tags                = local.common_tags

  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "Http5xx"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 10
  }

  action {
    action_group_id = azurerm_monitor_action_group.platform.id
  }
}
