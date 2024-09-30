module "application_gateway" {
  source = "../modules/terraform-azurerm-application-gateway"

  # (required) general configuration used for naming resources, location etc
  general = {
    prefix         = "c4c"
    application    = "connectivity"
    environment    = "prd"
    location       = "westeurope"
    resource_group = data.azurerm_resource_group.example.name
  }

  # (optional) the tags that will be applied once during the creation of the resources
  tags = {
    environment = "prd"
    location    = "westeurope"
    managed_by  = "terraform"
  }

  # (required) The ip configuration of the application gateway.
  # azure portal location: overview => virtual network/subnet
  gateway_ip_configuration = {
    subnet = data.azurerm_subnet.example.id
  }

  # (required) create backend address pools
  # azure portal location: settings => backend pools
  backend_address_pools = [
    {
      name         = "backend_prd"
      ip_addresses = ["10.16.0.10", "10.16.0.11"]
    },
    {
      name  = "backend_acc"
      fqdns = ["acc.example.nl"]
    }
  ]

  # (required) create backend http settings
  # azure portal location: settings => backend settings
  backend_http_settings = [
    {
      name                  = "HTTP-PRD"
      cookie_based_affinity = "Disabled"
      port                  = 80
      protocol              = "Http"
    },
    {
      name                  = "HTTPS-PRD"
      cookie_based_affinity = "Disabled"
      port                  = 443
      protocol              = "Https"
    },
    {
      name                  = "HTTP-ACC"
      cookie_based_affinity = "Disabled"
      port                  = 80
      protocol              = "Http"
    },
    {
      name                  = "HTTPS-ACC"
      cookie_based_affinity = "Disabled"
      port                  = 443
      protocol              = "Https"
    }
  ]

  # (optional) create ssl certificates
  # azure portal location: settings => listeners => listener tls certificates
  ssl_certificates = [
    {
      name     = "prd.example.nl"
      data     = "./certificates/prd.example.nl.pfx" # upload directly from repository
      password = "Welkom@1234!"                      # password should be set via CI/CD pipeline variable
    },
    {
      name                = "acc.example.nl"
      key_vault_secret_id = "https://example.vault.azure.net/secrets/prd/70734f7d86a14500b92428cfced4d155" # obtain from key vault (the user-assigned managed identity needs 'Key Vault Certificate User' permissions on the key vault)
    }
  ]

  # (required) create http listeners
  # azure portal location: settings => listeners
  http_listeners = [
    {
      name      = "HTTP-PRD"
      host_name = "prd.example.nl"
    },
    {
      name                 = "HTTPS-PRD"
      host_name            = "prd.example.nl"
      ssl_certificate_name = "prd.example.nl" # make sure the ssl certificate is configured by the ssl_certificates variable
    },
    {
      name      = "HTTP-ACC"
      host_name = "acc.example.nl"
    },
    {
      name                 = "HTTPS-ACC"
      host_name            = "acc.example.nl"
      ssl_certificate_name = "acc.example.nl" # make sure the ssl certificate is configured by the ssl_certificates variable
    }
  ]

  # (required) create request routing rules
  # azure portal location: settings => rules
  request_routing_rules = [
    {
      name                       = "HTTP-PRD"
      priority                   = 1
      rule_type                  = "Basic"
      http_listener_name         = "HTTP-PRD"    # make sure the http listener is configured by the http_listeners variable
      backend_address_pool_name  = "backend_prd" # make sure the backend address pool is configured by the backend_address_pool variable
      backend_http_settings_name = "HTTP-PRD"    # make sure the backend http setting is configured by the backend_http_settings variable
    },
    {
      name                       = "HTTPS-PRD"
      priority                   = 3
      rule_type                  = "Basic"
      http_listener_name         = "HTTPS-PRD"
      backend_address_pool_name  = "backend_prd"
      backend_http_settings_name = "HTTPS-PRD"
    },
    {
      name                       = "HTTP-ACC"
      priority                   = 2
      rule_type                  = "Basic"
      http_listener_name         = "HTTP-ACC"
      backend_address_pool_name  = "backend_acc"
      backend_http_settings_name = "HTTP-ACC"
    },
    {
      name                       = "HTTPS-ACC"
      priority                   = 4
      rule_type                  = "Basic"
      http_listener_name         = "HTTPS-ACC"
      backend_address_pool_name  = "backend_acc"
      backend_http_settings_name = "HTTPS-ACC"
    }
  ]
}
