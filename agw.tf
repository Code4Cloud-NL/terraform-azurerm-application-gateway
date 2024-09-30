locals {
  frontend_ip_configuration_name = "${local.prefix}-agw-feip-${local.suffix}-${var.instance}"
  frontend_port_80_name          = "${local.prefix}-agw-feport-80-${local.suffix}-${var.instance}"
  frontend_port_443_name         = "${local.prefix}-agw-feport-443-${local.suffix}-${var.instance}"
  gateway_ip_configuration_name  = "${local.prefix}-agw-gwipc-${local.suffix}-${var.instance}"
}

# create application gateway
resource "azurerm_application_gateway" "this" {
  name                = "${local.prefix}-agw-${local.suffix}-${var.instance}"
  location            = var.general.location
  resource_group_name = var.general.resource_group.name
  tags                = var.tags
  zones               = var.availability_zones
  enable_http2        = var.enable_http2

  # (required) configure sku, tier and capacity
  # azure portal location: settings => configuration
  sku {
    name     = var.sku.name
    tier     = var.sku.tier
    capacity = var.autoscale_configuration == null ? var.sku.capacity : null
  }

  # (optional) enable and configure autoscale
  # azure portal location: settings => configuration
  dynamic "autoscale_configuration" {
    for_each = var.autoscale_configuration[*]
    content {
      min_capacity = autoscale_configuration.value.min_capacity
      max_capacity = autoscale_configuration.value.max_capacity
    }
  }

  # (required) create frontend ip configuration
  # azure portal location: settings => frontend ip configurations
  frontend_ip_configuration {
    name                          = local.frontend_ip_configuration_name
    public_ip_address_id          = azurerm_public_ip.this.id
    subnet_id                     = try(var.frontend_ip_configuration.subnet.id, null)
    private_ip_address            = try(var.frontend_ip_configuration.private_ip_address, null)
    private_ip_address_allocation = try(var.frontend_ip_configuration.private_ip_address_allocation, null)
  }

  # create gateway ip configuration (vnet/subnet)
  # azure portal location: overview => virtual network/subnet
  gateway_ip_configuration {
    name      = local.gateway_ip_configuration_name
    subnet_id = var.gateway_ip_configuration.subnet.id
  }

  # (required) create backend address pools
  # azure portal location: settings => backend pools
  dynamic "backend_address_pool" {
    for_each = var.backend_address_pools
    content {
      name         = backend_address_pool.value.name
      fqdns        = backend_address_pool.value.fqdns
      ip_addresses = backend_address_pool.value.ip_addresses
    }
  }

  # (required) create backend http settings
  # azure portal location: settings => backend settings
  dynamic "backend_http_settings" {
    for_each = var.backend_http_settings
    content {
      name                                = backend_http_settings.value.name
      cookie_based_affinity               = backend_http_settings.value.cookie_based_affinity
      affinity_cookie_name                = backend_http_settings.value.affinity_cookie_name
      path                                = backend_http_settings.value.path
      port                                = backend_http_settings.value.port
      probe_name                          = backend_http_settings.value.probe_name
      protocol                            = backend_http_settings.value.protocol
      request_timeout                     = backend_http_settings.value.request_timeout
      host_name                           = backend_http_settings.value.host_name
      pick_host_name_from_backend_address = backend_http_settings.value.pick_host_name_from_backend_address
      trusted_root_certificate_names      = backend_http_settings.value.trusted_root_certificate_names

      # (optional) configure authentication certificates on backend http setting
      dynamic "authentication_certificate" {
        for_each = backend_http_settings.value.authentication_certificate[*]
        content {
          name = authentication_certificate.value.name
        }
      }

      # (optional) configure and enable connection draining on backend http setting
      # azure portal location: settings => backend settings => backend setting => connection draining
      dynamic "connection_draining" {
        for_each = backend_http_settings.value.connection_draining[*]
        content {
          enabled           = connection_draining.value.enabled
          drain_timeout_sec = connection_draining.value.drain_timeout_sec
        }
      }
    }
  }

  # (optional) create trusted root certificates
  # azure portal location: settings => backend settings => backend server's certificate is issued by a well-known ca => no => upload root ca certificate
  dynamic "trusted_root_certificate" {
    for_each = var.trusted_root_certificates
    content {
      name                = trusted_root_certificate.value.name
      data                = try(filebase64(trusted_root_certificate.value.data), null)
      key_vault_secret_id = trusted_root_certificate.value.key_vault_secret_id
    }
  }

  # create frontend port for port 80
  frontend_port {
    name = local.frontend_port_80_name
    port = 80
  }

  # create frontend port for port 443
  frontend_port {
    name = local.frontend_port_443_name
    port = 443
  }

  # (required) create http listeners
  # azure portal location: settings => listeners
  dynamic "http_listener" {
    for_each = var.http_listeners
    content {
      name                           = http_listener.value.name
      frontend_ip_configuration_name = local.frontend_ip_configuration_name
      frontend_port_name             = http_listener.value.ssl_certificate_name == null ? local.frontend_port_80_name : local.frontend_port_443_name
      host_name                      = lookup(http_listener.value, "host_name", null)
      host_names                     = lookup(http_listener.value, "host_names", null)
      protocol                       = http_listener.value.ssl_certificate_name == null ? "Http" : "Https"
      require_sni                    = http_listener.value.ssl_certificate_name == null ? http_listener.value.require_sni : null
      ssl_certificate_name           = http_listener.value.ssl_certificate_name
      firewall_policy_id             = http_listener.value.firewall_policy_id
      ssl_profile_name               = http_listener.value.ssl_profile_name

      # (optional) configure custom error pages
      # azure portal location: settings => listeners => listener => custom error pages
      dynamic "custom_error_configuration" {
        for_each = http_listener.value.custom_error_pages
        content {
          status_code           = "HttpStatus${custom_error_configuration.value.status_code}"
          custom_error_page_url = custom_error_configuration.value.custom_error_page_url
        }
      }
    }
  }

  # (optional) create ssl certificates
  # azure portal location: settings => listeners => listener tls certificates
  dynamic "ssl_certificate" {
    for_each = var.ssl_certificates
    content {
      name                = ssl_certificate.value.name
      data                = try(filebase64(ssl_certificate.value.data), null)
      password            = ssl_certificate.value.password
      key_vault_secret_id = ssl_certificate.value.key_vault_secret_id
    }
  }

  # configure the default ssl policy for the application gateway
  # azure portal location: settings => listeners
  ssl_policy {
    policy_type          = var.ssl_policy.policy_type
    policy_name          = var.ssl_policy.policy_type == "Predefined" ? var.ssl_policy.policy_name : null
    cipher_suites        = var.ssl_policy.cipher_suites
    min_protocol_version = var.ssl_policy.min_protocol_version
  }

  # (optional) create ssl profiles
  # azure portal location: settings => ssl settings
  dynamic "ssl_profile" {
    for_each = var.ssl_profiles
    content {
      name                                 = ssl_profile.value.name
      trusted_client_certificate_names     = ssl_profile.value.trusted_client_certificate_names
      verify_client_cert_issuer_dn         = ssl_profile.value.verify_client_cert_issuer_dn
      verify_client_certificate_revocation = ssl_profile.value.verify_client_certificate_revocation

      # (optional) configure a custom ssl policy (only used when you want stronger encryption than the application gateway default)
      # azure portal location: settings => ssl settings => ssl profile => ssl policy
      dynamic "ssl_policy" {
        for_each = ssl_profile.value.ssl_policy[*]
        content {
          policy_type          = ssl_policy.value.policy_type
          policy_name          = ssl_policy.value.policy_name
          cipher_suites        = ssl_policy.value.cipher_suites
          min_protocol_version = ssl_policy.value.min_protocol_version
        }
      }
    }
  }

  # (optional) create trusted client certificates
  # azure portal location: settings => ssl settings => + ssl profiles => client authentication => certificates
  dynamic "trusted_client_certificate" {
    for_each = var.trusted_client_certificates
    content {
      name = trusted_client_certificate.value.name
      data = filebase64(trusted_client_certificate.value.data)
    }
  }

  # (optional) create authentication certificates
  dynamic "authentication_certificate" {
    for_each = var.authentication_certificates
    content {
      name = authentication_certificate.value.name
      data = filebase64(authentication_certificate.value.data)
    }
  }

  # assign the user-assigned managed identity (created from within this module) to the application gateway
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.this.id]
  }

  # (required) create request routing rules
  # azure portal location: settings => rules
  dynamic "request_routing_rule" {
    for_each = var.request_routing_rules
    content {
      name                        = request_routing_rule.value.name
      priority                    = request_routing_rule.value.priority
      rule_type                   = request_routing_rule.value.rule_type
      http_listener_name          = request_routing_rule.value.http_listener_name
      backend_address_pool_name   = request_routing_rule.value.redirect_configuration_name == null ? request_routing_rule.value.backend_address_pool_name : null
      backend_http_settings_name  = request_routing_rule.value.redirect_configuration_name == null ? request_routing_rule.value.backend_http_settings_name : null
      redirect_configuration_name = request_routing_rule.value.redirect_configuration_name
      rewrite_rule_set_name       = request_routing_rule.value.rewrite_rule_set_name
      url_path_map_name           = request_routing_rule.value.url_path_map_name
    }
  }

  # (optional) create url path maps
  # azure portal location: settings => rules => routing rule => backend targets => path-based routing => add multiple targets to create a path-based rule
  dynamic "url_path_map" {
    for_each = var.url_path_maps
    content {
      name                                = url_path_map.value.name
      default_backend_address_pool_name   = url_path_map.value.default_backend_address_pool_name
      default_backend_http_settings_name  = url_path_map.value.default_backend_http_settings_name
      default_redirect_configuration_name = url_path_map.value.default_redirect_configuration_name
      default_rewrite_rule_set_name       = url_path_map.value.default_rewrite_rule_set_name

      dynamic "path_rule" {
        for_each = url_path_map.value.path_rules
        content {
          name                        = path_rule.value.name
          paths                       = path_rule.value.paths
          backend_address_pool_name   = path_rule.value.backend_address_pool_name
          backend_http_settings_name  = path_rule.value.backend_http_settings_name
          redirect_configuration_name = path_rule.value.redirect_configuration_name
          rewrite_rule_set_name       = path_rule.value.rewrite_rule_set_name
          firewall_policy_id          = path_rule.value.firewall_policy_id
        }
      }
    }
  }

  # (optional) create redirect configurations
  # azure portal location: settings => rules => routing rule => backend targets => redirection
  dynamic "redirect_configuration" {
    for_each = var.redirect_configurations
    content {
      name                 = redirect_configuration.value.name
      redirect_type        = redirect_configuration.value.redirect_type
      target_listener_name = redirect_configuration.value.target_listener_name
      target_url           = redirect_configuration.value.target_url
      include_path         = redirect_configuration.value.include_path
      include_query_string = redirect_configuration.value.include_query_string
    }
  }

  # (optional) create rewrite rule sets
  # azure portal location: settings => rewrites
  dynamic "rewrite_rule_set" {
    for_each = var.rewrite_rule_sets
    content {
      name = rewrite_rule_set.value.name

      # (optional) create rewrite rules
      dynamic "rewrite_rule" {
        for_each = rewrite_rule_set.value.rewrite_rules
        content {
          name          = rewrite_rule.value.name
          rule_sequence = rewrite_rule.value.rule_sequence

          # (optional) create conditions
          dynamic "condition" {
            for_each = rewrite_rule.value.conditions
            content {
              variable    = condition.value.variable
              pattern     = condition.value.pattern
              ignore_case = condition.value.ignore_case
              negate      = condition.value.negate
            }
          }

          # (optional) create request header configurations
          dynamic "request_header_configuration" {
            for_each = rewrite_rule.value.request_header_configurations
            content {
              header_name  = request_header_configuration.value.header_name
              header_value = request_header_configuration.value.header_value
            }
          }

          # (optional) create response header configurations
          dynamic "response_header_configuration" {
            for_each = rewrite_rule.value.response_header_configurations
            content {
              header_name  = response_header_configuration.value.header_name
              header_value = response_header_configuration.value.header_value
            }
          }

          # (optional) create url configurations
          dynamic "url" {
            for_each = rewrite_rule.value.url
            content {
              path         = url.value.path
              query_string = url.value.query_string
              components   = url.value.components
              reroute      = url.value.reroute
            }
          }
        }
      }
    }
  }

  # (optional) create health probes
  # azure portal location: settings => health probes
  dynamic "probe" {
    for_each = var.health_probes
    content {
      name                                      = probe.value.name
      protocol                                  = probe.value.protocol
      pick_host_name_from_backend_http_settings = probe.value.pick_host_name_from_backend_http_settings
      host                                      = probe.value.host
      port                                      = probe.value.port
      path                                      = probe.value.path
      interval                                  = probe.value.interval
      timeout                                   = probe.value.timeout
      unhealthy_threshold                       = probe.value.unhealthy_threshold

      # (optional) use probe matching conditions
      # azure portal location: settings => health probes => health probe => use probe mathcing conditions => yes
      dynamic "match" {
        for_each = probe.value.matching_conditions[*]
        content {
          body        = match.value.body
          status_code = match.value.status_code
        }
      }
    }
  }

  # configure web application firewall
  # azure portal location: settings => web application firewall
  dynamic "waf_configuration" {
    for_each = var.sku.tier == "WAF_v2" ? var.waf_configuration[*] : []
    content {
      enabled                  = var.waf_configuration.enabled
      firewall_mode            = var.waf_configuration.firewall_mode
      rule_set_type            = var.waf_configuration.rule_set_type
      rule_set_version         = var.waf_configuration.rule_set_version
      file_upload_limit_mb     = var.waf_configuration.file_upload_limit_mb
      request_body_check       = var.waf_configuration.request_body_check
      max_request_body_size_kb = var.waf_configuration.max_request_body_size_kb

      # (optional) disable one or more rule groups or rules
      # azure portal location: settings => web application firewall => rules => advanced rule configuration => Enabled
      dynamic "disabled_rule_group" {
        for_each = var.waf_configuration.disabled_rule_groups
        content {
          rule_group_name = disabled_rule_group.value.rule_group_name
          rules           = disabled_rule_group.value.rules
        }
      }

      # (optional) create one or more exclusions
      # azure portal location: settings => web application firewall => configure => exclusions
      dynamic "exclusion" {
        for_each = var.waf_configuration.exclusions
        content {
          match_variable          = exclusion.value.match_variable
          selector_match_operator = exclusion.value.selector_match_operator
          selector                = exclusion.value.selector
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [tags]
  }
}
