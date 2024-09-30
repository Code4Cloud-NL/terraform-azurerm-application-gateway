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

  # (optional) create trusted root certificates
  # azure portal location: settings => backend settings => backend server's certificate is issued by a well-known ca => no => upload root ca certificate
  trusted_root_certificates = [
    {
      name = "verisign_root_ca"
      data = "./certificates/verisign.cer" # upload directly from repository
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
      probe_name            = "HTTP-PRD"
    },
    {
      name                           = "HTTPS-PRD"
      cookie_based_affinity          = "Disabled"
      port                           = 443
      protocol                       = "Https"
      trusted_root_certificate_names = ["verisign_root_ca"] # make sure the certificates are configured by the trusted_root_certificates variable
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

  # (optional) create health probes
  # azure portal location: settings => health probes
  health_probes = [
    {
      name     = "HTTP-PRD"
      protocol = "Http"
      path     = "/test.html"
      host     = "prd.example.nl"
      matching_conditions = {
        body        = "productie"
        status_code = ["200-399"]
      }
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
      ssl_profile_name     = "SSL-PRD"        # make sure the ssl profile is configured by the ssl_profiles variable
    },
    {
      name      = "HTTP-ACC"
      host_name = "acc.example.nl"
      custom_error_pages = [
        { status_code = "403", custom_error_page_url = "http://acc.example.nl/forbidden.html" },   # make sure the url is resolvable before configuring
        { status_code = "502", custom_error_page_url = "http://acc.example.nl/bad_gateway.html" }, # make sure the url is resolvable before configuring
      ]
    },
    {
      name                 = "HTTPS-ACC"
      host_name            = "acc.example.nl"
      ssl_certificate_name = "acc.example.nl" # make sure the ssl certificate is configured by the ssl_certificates variable
    }
  ]

  # (optional) create trusted client certificates
  # azure portal location: settings => ssl settings => + ssl profiles => client authentication => certificates
  trusted_client_certificates = [
    {
      name = "client_cert"
      data = "./certificates/client.cer" # upload directly from repository
    },
    {
      name = "client_cert_backup"
      data = "./certificates/client_backup.cer" # upload directly from repository
    }
  ]

  # (optional) create ssl profiles
  # azure portal location: settings => ssl settings
  ssl_profiles = [
    {
      name                             = "SSL-PRD"
      trusted_client_certificate_names = ["client_cert", "client_cert_backup"] # make sure the certificate is configured by the trusted_client_certificates variable
      verify_client_cert_issuer_dn     = true
      ssl_policy = {
        policy_type = "Predefined"
        policy_name = "AppGwSslPolicy20220101S"
      }
    }
  ]

  # (required) create request routing rules
  # azure portal location: settings => rules
  request_routing_rules = [
    {
      name                       = "HTTP-PRD"
      priority                   = 1
      rule_type                  = "Basic"
      http_listener_name         = "HTTP-PRD"     # make sure the http listener is configured by the http_listeners variable
      backend_address_pool_name  = "backend_prd"  # make sure the backend address pool is configured by the backend_address_pool variable
      backend_http_settings_name = "HTTP-PRD"     # make sure the backend http setting is configured by the backend_http_settings variable
      url_path_map_name          = "PATH-MAP-PRD" # make sure the url path map is configured by the url_path_maps variable
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
      name                        = "HTTP-ACC"
      priority                    = 2
      rule_type                   = "Basic"
      http_listener_name          = "HTTP-ACC"
      redirect_configuration_name = "REDIRECT-PRD" # make sure the redirect configuration name is configured by the redirect_configurations variable
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

  # (optional) create url path maps
  # azure portal location: settings => rules => routing rule => backend targets => path-based routing => add multiple targets to create a path-based rule
  url_path_maps = [
    {
      name                               = "PATH-MAP-PRD" # make sure the url path map is configured by the url_path_maps variable
      default_backend_address_pool_name  = "backend_prd"  # make sure the backend address pool is configured by the backend_address_pool variable
      default_backend_http_settings_name = "HTTP-PRD"     # make sure the backend http setting is configured by the backend_http_settings variable
      path_rules = [
        {
          name                       = "RULE-PRD"
          paths                      = ["/productie", "/prd"]
          backend_address_pool_name  = "backend_prd" # make sure the backend address pool is configured by the backend_address_pool variable
          backend_http_settings_name = "HTTP-PRD"    # make sure the backend http setting is configured by the backend_http_settings variable
        }
      ]
    }
  ]

  # (optional) create redirect configurations
  # azure portal location: settings => rules => routing rule => backend targets => redirection
  redirect_configurations = [
    {
      name                 = "REDIRECT-PRD"
      redirect_type        = "Permanent"
      target_listener_name = "HTTP-PRD" # make sure the http listener is configured by the http_listeners variable
    }
  ]

  # (optional) create rewrite rule sets
  # azure portal location: settings => rewrites
  rewrite_rule_sets = [
    {
      name = "SET-PRD"
      rewrite_rules = [
        {
          name          = "RULE-PRD-001"
          rule_sequence = 100
          request_header_configurations = [
            {
              header_name  = "Accept"
              header_value = "test_value"
            }
          ]
        },
      ]
    }
  ]


  # (optional) configure web application firewall
  # azure portal location: settings => web application firewall
  waf_configuration = {
    disabled_rule_groups = [
      {
        rule_group_name = "REQUEST-913-SCANNER-DETECTION"
      },
      {
        rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
        rules           = ["920100", "920120"]
      }
    ]
    exclusions = [
      {
        match_variable          = "RequestArgNames"
        selector_match_operator = "Contains"
        selector                = "productie"
      },
      {
        match_variable          = "RequestCookieNames"
        selector_match_operator = "StartsWith"
        selector                = "p"
      },
      {
        match_variable = "RequestHeaderNames"
      }
    ]
  }
}
