<!-- BEGIN_TF_DOCS -->
# Azure Application Gateway module

This module simplifies the creation of an Application Gateway in Azure. It is designed to be flexible, modular, and easy to use, ensuring a seamless Azure Application Gateway deployment.

## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | n/a |

## Resources

| Name | Type |
|------|------|
| [azurerm_application_gateway.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway) | resource |
| [azurerm_log_analytics_workspace.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/log_analytics_workspace) | resource |
| [azurerm_monitor_diagnostic_setting.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting) | resource |
| [azurerm_public_ip.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/public_ip) | resource |
| [azurerm_user_assigned_identity.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/user_assigned_identity) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_authentication_certificates"></a> [authentication\_certificates](#input\_authentication\_certificates) | Authentication certificates for usage by the backends. | <pre>list(object({<br>    name = string<br>    data = string<br>  }))</pre> | `[]` | no |
| <a name="input_autoscale_configuration"></a> [autoscale\_configuration](#input\_autoscale\_configuration) | Configure autoscaling on the application gateway. | <pre>object({<br>    min_capacity = number<br>    max_capacity = number<br>  })</pre> | `null` | no |
| <a name="input_availability_zones"></a> [availability\_zones](#input\_availability\_zones) | A list of Availability Zones in which this Application Gateway should be located. | `list(number)` | `null` | no |
| <a name="input_backend_address_pools"></a> [backend\_address\_pools](#input\_backend\_address\_pools) | One or more backend address pools. | <pre>list(object({<br>    name         = string<br>    fqdns        = optional(list(string))<br>    ip_addresses = optional(list(string))<br>  }))</pre> | n/a | yes |
| <a name="input_backend_http_settings"></a> [backend\_http\_settings](#input\_backend\_http\_settings) | One or more backend HTTP settings. | <pre>list(object({<br>    name                                = string<br>    cookie_based_affinity               = string<br>    affinity_cookie_name                = optional(string)<br>    path                                = optional(string)<br>    port                                = number<br>    probe_name                          = optional(string)<br>    protocol                            = string<br>    request_timeout                     = optional(number, 30)<br>    host_name                           = optional(string)<br>    pick_host_name_from_backend_address = optional(bool, false)<br>    trusted_root_certificate_names      = optional(list(string))<br>    authentication_certificate = optional(object({<br>      name = string<br>    }))<br>    connection_draining = optional(object({<br>      enabled           = optional(bool, false)<br>      drain_timeout_sec = optional(number, 600)<br>    }))<br>  }))</pre> | n/a | yes |
| <a name="input_enable_http2"></a> [enable\_http2](#input\_enable\_http2) | Enable HTTP2 on the application gateway resource? | `bool` | `false` | no |
| <a name="input_frontend_ip_configuration"></a> [frontend\_ip\_configuration](#input\_frontend\_ip\_configuration) | The frontend ip configuration of the application gateway. | <pre>object({<br>    subnet = optional(object({<br>      id = string<br>    }))<br>    private_ip_address            = string<br>    private_ip_address_allocation = optional(string, "Static")<br>  })</pre> | `null` | no |
| <a name="input_gateway_ip_configuration"></a> [gateway\_ip\_configuration](#input\_gateway\_ip\_configuration) | The ip configuration of the application gateway. | <pre>object({<br>    subnet = object({<br>      id = string<br>    })<br>  })</pre> | n/a | yes |
| <a name="input_general"></a> [general](#input\_general) | General configuration used for naming resources, location etc. | <pre>object({<br>    prefix      = string<br>    application = string<br>    environment = string<br>    location    = string<br>    resource_group = object({<br>      name = string<br>    })<br>  })</pre> | n/a | yes |
| <a name="input_health_probes"></a> [health\_probes](#input\_health\_probes) | Health probes for usage by the backends. | <pre>list(object({<br>    name                                      = string<br>    protocol                                  = string<br>    pick_host_name_from_backend_http_settings = optional(bool, false)<br>    host                                      = optional(string)<br>    port                                      = optional(number)<br>    path                                      = string<br>    interval                                  = optional(number, 30)<br>    timeout                                   = optional(number, 30)<br>    unhealthy_threshold                       = optional(number, 3)<br>    matching_conditions = optional(object({<br>      body        = string<br>      status_code = list(string)<br>    }))<br>  }))</pre> | `[]` | no |
| <a name="input_http_listeners"></a> [http\_listeners](#input\_http\_listeners) | One or more HTTP listeners. | <pre>list(object({<br>    name                 = string<br>    host_name            = optional(string)<br>    host_names           = optional(list(string))<br>    require_sni          = optional(bool)<br>    ssl_certificate_name = optional(string)<br>    firewall_policy_id   = optional(string)<br>    ssl_profile_name     = optional(string)<br>    custom_error_pages = optional(list(object({<br>      status_code           = string<br>      custom_error_page_url = string<br>    })), [])<br>  }))</pre> | n/a | yes |
| <a name="input_instance"></a> [instance](#input\_instance) | The instance number used in the naming of the application gateway resources. | `string` | `"001"` | no |
| <a name="input_log_retention_in_days"></a> [log\_retention\_in\_days](#input\_log\_retention\_in\_days) | The retention in days for the log analytic workspace. | `number` | `90` | no |
| <a name="input_redirect_configurations"></a> [redirect\_configurations](#input\_redirect\_configurations) | List of redirects used associated to backend targets on request routing rules. | <pre>list(object({<br>    name                 = string<br>    redirect_type        = string<br>    target_listener_name = optional(string)<br>    target_url           = optional(string)<br>    include_path         = optional(bool, true)<br>    include_query_string = optional(bool, true)<br>  }))</pre> | `[]` | no |
| <a name="input_request_routing_rules"></a> [request\_routing\_rules](#input\_request\_routing\_rules) | One or more request routing rules to be used for HTTP listeners. | <pre>list(object({<br>    name                        = string<br>    priority                    = number<br>    rule_type                   = string<br>    http_listener_name          = string<br>    backend_address_pool_name   = optional(string)<br>    backend_http_settings_name  = optional(string)<br>    redirect_configuration_name = optional(string)<br>    rewrite_rule_set_name       = optional(string)<br>    url_path_map_name           = optional(string)<br>  }))</pre> | n/a | yes |
| <a name="input_rewrite_rule_sets"></a> [rewrite\_rule\_sets](#input\_rewrite\_rule\_sets) | List of rewrite rule sets. | <pre>list(object({<br>    name = string<br>    rewrite_rules = optional(list(object({<br>      name          = string<br>      rule_sequence = number<br>      conditions = optional(list(object({<br>        variable    = string<br>        pattern     = string<br>        ignore_case = optional(bool, false)<br>        negate      = optional(bool, false)<br>      })), [])<br>      request_header_configurations = optional(list(object({<br>        header_name  = string<br>        header_value = string<br>      })), [])<br>      response_header_configurations = optional(list(object({<br>        header_name  = string<br>        header_value = string<br>      })), [])<br>      url = optional(list(object({<br>        path         = optional(string)<br>        query_string = optional(string)<br>        components   = optional(string)<br>        reroute      = optional(bool, false)<br>      })), [])<br>    })))<br>  }))</pre> | `[]` | no |
| <a name="input_sku"></a> [sku](#input\_sku) | The name, tier and capacity of the Application Gateway. | <pre>object({<br>    name     = optional(string, "WAF_v2")<br>    tier     = optional(string, "WAF_v2")<br>    capacity = optional(number, 2)<br>  })</pre> | <pre>{<br>  "capacity": 2,<br>  "name": "WAF_v2",<br>  "tier": "WAF_v2"<br>}</pre> | no |
| <a name="input_ssl_certificates"></a> [ssl\_certificates](#input\_ssl\_certificates) | SSL certificates for usage by the HTTP listeners. | <pre>list(object({<br>    name                = string<br>    data                = optional(string)<br>    password            = optional(string)<br>    key_vault_secret_id = optional(string)<br>  }))</pre> | `[]` | no |
| <a name="input_ssl_policy"></a> [ssl\_policy](#input\_ssl\_policy) | The default ssl policy for the application gateway. | <pre>object({<br>    policy_type          = string<br>    policy_name          = optional(string)<br>    cipher_suites        = optional(list(string))<br>    min_protocol_version = optional(string)<br>  })</pre> | <pre>{<br>  "policy_name": "AppGwSslPolicy20220101",<br>  "policy_type": "Predefined"<br>}</pre> | no |
| <a name="input_ssl_profiles"></a> [ssl\_profiles](#input\_ssl\_profiles) | One or more SSL profiles for usage by HTTPS listeners. | <pre>list(object({<br>    name                                 = string<br>    trusted_client_certificate_names     = optional(list(string))<br>    verify_client_cert_issuer_dn         = optional(bool, false)<br>    verify_client_certificate_revocation = optional(string)<br>    ssl_policy = optional(object({<br>      policy_type          = optional(string)<br>      policy_name          = optional(string)<br>      cipher_suites        = optional(list(string))<br>      min_protocol_version = optional(string)<br>    }))<br>  }))</pre> | `[]` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | The tags that will be applied once during the creation of the resources. | `map(string)` | `{}` | no |
| <a name="input_trusted_client_certificates"></a> [trusted\_client\_certificates](#input\_trusted\_client\_certificates) | Trusted client certificates for usage by the ssl profiles. | <pre>list(object({<br>    name = string<br>    data = optional(string)<br>  }))</pre> | `[]` | no |
| <a name="input_trusted_root_certificates"></a> [trusted\_root\_certificates](#input\_trusted\_root\_certificates) | Trusted root certificates for usage by the backends. | <pre>list(object({<br>    name                = string<br>    data                = optional(string)<br>    key_vault_secret_id = optional(string)<br>  }))</pre> | `[]` | no |
| <a name="input_url_path_maps"></a> [url\_path\_maps](#input\_url\_path\_maps) | List of URL path maps associated to path-based rules. | <pre>list(object({<br>    name                                = string<br>    default_backend_address_pool_name   = optional(string)<br>    default_backend_http_settings_name  = optional(string)<br>    default_redirect_configuration_name = optional(string)<br>    default_rewrite_rule_set_name       = optional(string)<br>    path_rules = list(object({<br>      name                        = string<br>      paths                       = list(string)<br>      backend_address_pool_name   = optional(string)<br>      backend_http_settings_name  = optional(string)<br>      redirect_configuration_name = optional(string)<br>      rewrite_rule_set_name       = optional(string)<br>      firewall_policy_id          = optional(string)<br>    }))<br>  }))</pre> | `[]` | no |
| <a name="input_waf_configuration"></a> [waf\_configuration](#input\_waf\_configuration) | The configuration of the web application firewall (WAF). Only used when SKU tier is set to WAF\_v2. | <pre>object({<br>    enabled                  = optional(bool, true)<br>    firewall_mode            = optional(string, "Prevention")<br>    rule_set_type            = optional(string, "OWASP")<br>    rule_set_version         = optional(string, "3.1")<br>    file_upload_limit_mb     = optional(number, 100)<br>    request_body_check       = optional(bool, true)<br>    max_request_body_size_kb = optional(number, 128)<br>    disabled_rule_groups = optional(list(object({<br>      rule_group_name = string<br>      rules           = optional(list(string))<br>    })), [])<br>    exclusions = optional(list(object({<br>      match_variable          = string<br>      selector_match_operator = optional(string)<br>      selector                = optional(string)<br>    })), [])<br>  })</pre> | <pre>{<br>  "enabled": true,<br>  "file_upload_limit_mb": 100,<br>  "firewall_mode": "Prevention",<br>  "max_request_body_size_kb": 128,<br>  "request_body_check": true,<br>  "rule_set_type": "OWASP",<br>  "rule_set_version": "3.1"<br>}</pre> | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_application_gateway_id"></a> [application\_gateway\_id](#output\_application\_gateway\_id) | The ID of the application gateway. |
| <a name="output_backend_address_pool_ids"></a> [backend\_address\_pool\_ids](#output\_backend\_address\_pool\_ids) | The ID's of the backend address pools. |
| <a name="output_backend_http_settings_ids"></a> [backend\_http\_settings\_ids](#output\_backend\_http\_settings\_ids) | The ID's of the backend http settings. |
| <a name="output_frontend_ip_configuration_ids"></a> [frontend\_ip\_configuration\_ids](#output\_frontend\_ip\_configuration\_ids) | The ID's of the frontend ip configuration. |
| <a name="output_frontend_port_ids"></a> [frontend\_port\_ids](#output\_frontend\_port\_ids) | The ID's of the frontend ports. |
| <a name="output_gateway_ip_configuration_ids"></a> [gateway\_ip\_configuration\_ids](#output\_gateway\_ip\_configuration\_ids) | The ID's of the application gateway ip configuration. |
| <a name="output_health_probe_ids"></a> [health\_probe\_ids](#output\_health\_probe\_ids) | The ID's of the health probes. |
| <a name="output_http_listener_ids"></a> [http\_listener\_ids](#output\_http\_listener\_ids) | The ID's of the http listeners. |
| <a name="output_http_listener_ssl_certificate_ids"></a> [http\_listener\_ssl\_certificate\_ids](#output\_http\_listener\_ssl\_certificate\_ids) | The ID's of the associated ssl certificates. |
| <a name="output_log_analytic_workspace-id"></a> [log\_analytic\_workspace-id](#output\_log\_analytic\_workspace-id) | The ID of the log analytic workspace. |
| <a name="output_public_ip_id"></a> [public\_ip\_id](#output\_public\_ip\_id) | The ID of the public ip address. |
| <a name="output_request_routing_rule_ids"></a> [request\_routing\_rule\_ids](#output\_request\_routing\_rule\_ids) | The ID's of the request routing rules. |
| <a name="output_rewrite_rule_set_ids"></a> [rewrite\_rule\_set\_ids](#output\_rewrite\_rule\_set\_ids) | The ID's of the rewrite rule sets. |
| <a name="output_ssl_certificate_ids"></a> [ssl\_certificate\_ids](#output\_ssl\_certificate\_ids) | The ID's of the ssl certificates. |
| <a name="output_ssl_profile_ids"></a> [ssl\_profile\_ids](#output\_ssl\_profile\_ids) | The ID's of the ssl profiles. |

## Example(s)

### Application Gateway with required inputs only

```hcl
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
```

### Application Gateway with (almost) all of the inputs configured (for reference purposes)

```hcl
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
```

# Known issues and limitations

- The backend_address_pool, backend_http_settings, http_listener, private_link_configuration, request_routing_rule, redirect_configuration, probe, ssl_certificate, and frontend_port properties are Sets as the service API returns these lists of objects in a different order from how the provider sends them. As Sets are stored using a hash, if one value is added or removed from the Set, Terraform considers the entire list of objects changed and the plan shows that it is removing every value in the list and re-adding it with the new information. Though Terraform is showing all the values being removed and re-added, we are not actually removing anything unless the user specifies a removal in the configfile. Source: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway.

# Author

Stefan Vonk (stefan.vonk@pinkelephant.nl) Technical Specialist

Pink Elephant B.V. Gooimeer 18 1411 DE Naarden Netherlands
<!-- END_TF_DOCS -->