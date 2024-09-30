variable "general" {
  description = "General configuration used for naming resources, location etc."
  type = object({
    prefix      = string
    application = string
    environment = string
    location    = string
    resource_group = object({
      name = string
    })
  })
  validation {
    condition     = contains(["lab", "stg", "dev", "tst", "acc", "prd"], var.general.environment)
    error_message = "Invalid environment specified!"
  }
  validation {
    condition     = contains(["northeurope", "westeurope"], var.general.location)
    error_message = "Invalid location specified!"
  }
}

variable "tags" {
  description = "The tags that will be applied once during the creation of the resources."
  type        = map(string)
  default     = {}
}

variable "instance" {
  description = "The instance number used in the naming of the application gateway resources."
  type        = string
  default     = "001"
  validation {
    condition     = length(var.instance) <= 3
    error_message = "Instance must not exceed 3 characters."
  }
}

variable "availability_zones" {
  description = "A list of Availability Zones in which this Application Gateway should be located. "
  type        = list(number)
  default     = null
}

variable "sku" {
  description = "The name, tier and capacity of the Application Gateway."
  type = object({
    name     = optional(string, "WAF_v2")
    tier     = optional(string, "WAF_v2")
    capacity = optional(number, 2)
  })
  default = {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }
  validation {
    condition     = contains(["Standard_Small", "Standard_Medium", "Standard_Large", "Standard_v2", "WAF_Medium", "WAF_Large", "WAF_v2"], var.sku.name)
    error_message = "Invalid sku name specified. Possible values are: Standard_Small, Standard_Medium, Standard_Large, Standard_v2, WAF_Medium, WAF_Large, and WAF_v2."
  }
  validation {
    condition     = contains(["Standard_v2", "WAF_v2"], var.sku.tier)
    error_message = "Invalid sku tier specified. Possible values are: Standard_v2, WAF_v2."
  }
  validation {
    condition     = var.sku.capacity >= 1 && var.sku.capacity <= 125
    error_message = "Invalid capacity specified. Number should be between 1 and 125."
  }
}

variable "enable_http2" {
  description = "Enable HTTP2 on the application gateway resource?"
  type        = bool
  default     = false
}

variable "autoscale_configuration" {
  description = "Configure autoscaling on the application gateway."
  type = object({
    min_capacity = number
    max_capacity = number
  })
  default = null
}

variable "frontend_ip_configuration" {
  description = "The frontend ip configuration of the application gateway."
  type = object({
    subnet = optional(object({
      id = string
    }))
    private_ip_address            = string
    private_ip_address_allocation = optional(string, "Static")
  })
  default = null
}

variable "gateway_ip_configuration" {
  description = "The ip configuration of the application gateway."
  type = object({
    subnet = object({
      id = string
    })
  })
}

variable "backend_address_pools" {
  description = "One or more backend address pools."
  type = list(object({
    name         = string
    fqdns        = optional(list(string))
    ip_addresses = optional(list(string))
  }))
}

variable "backend_http_settings" {
  description = "One or more backend HTTP settings."
  type = list(object({
    name                                = string
    cookie_based_affinity               = string
    affinity_cookie_name                = optional(string)
    path                                = optional(string)
    port                                = number
    probe_name                          = optional(string)
    protocol                            = string
    request_timeout                     = optional(number, 30)
    host_name                           = optional(string)
    pick_host_name_from_backend_address = optional(bool, false)
    trusted_root_certificate_names      = optional(list(string))
    authentication_certificate = optional(object({
      name = string
    }))
    connection_draining = optional(object({
      enabled           = optional(bool, false)
      drain_timeout_sec = optional(number, 600)
    }))
  }))
  validation {
    condition = alltrue([
      for settings in var.backend_http_settings :
      contains(["Enabled", "Disabled"], settings.cookie_based_affinity)
    ])
    error_message = "Invalid cookie based affinity value. Possible values are: Enabled, Disabled."
  }
  validation {
    condition = alltrue([
      for settings in var.backend_http_settings :
      contains(["Http", "Https"], settings.protocol)
    ])
    error_message = "Invalid cookie based affinity value. Possible values are: Http, Https."
  }
  validation {
    condition = alltrue([
      for settings in var.backend_http_settings :
      settings.request_timeout >= 1 && settings.request_timeout <= 86400
    ])
    error_message = "Request timeout value must be between 1 and 86400 seconds."
  }
  validation {
    condition = alltrue([
      for settings in var.backend_http_settings : settings.host_name == null ? true : (
        settings.host_name != null && settings.pick_host_name_from_backend_address == false
      )
    ])
    error_message = "Host header cannot be set if pick_host_name_from_backend_address is set to true."
  }
}

variable "ssl_certificates" {
  description = "SSL certificates for usage by the HTTP listeners."
  type = list(object({
    name                = string
    data                = optional(string)
    password            = optional(string)
    key_vault_secret_id = optional(string)
  }))
  default = []
  validation {
    condition = alltrue([
      for cert in var.ssl_certificates : var.ssl_certificates == null ? true : (
        (cert.data == null && cert.key_vault_secret_id != null) ||
        (cert.data != null && cert.key_vault_secret_id == null)
      )
    ])
    error_message = "Either specify a PFX file using data, or specify a KeyVault secret ID, not both."
  }
  validation {
    condition = alltrue([
      for cert in var.ssl_certificates : var.ssl_certificates == null ? true : (
        (cert.data == null && cert.password == null) ||
        (cert.data != null && cert.password != null)
      )
    ])
    error_message = "PFX password is required when using data."
  }
}

variable "http_listeners" {
  description = "One or more HTTP listeners."
  type = list(object({
    name                 = string
    host_name            = optional(string)
    host_names           = optional(list(string))
    require_sni          = optional(bool)
    ssl_certificate_name = optional(string)
    firewall_policy_id   = optional(string)
    ssl_profile_name     = optional(string)
    custom_error_pages = optional(list(object({
      status_code           = string
      custom_error_page_url = string
    })), [])
  }))
  validation {
    condition = alltrue([
      for settings in var.http_listeners : (
        (settings.host_name == null && settings.host_names == null) ||
        (settings.host_name != null && settings.host_names == null) ||
        (settings.host_name == null && settings.host_names != null)
      )
    ])
    error_message = "The host names and host name arguments are mutually exclusive and cannot both be set."
  }
  validation {
    condition = alltrue([
      for settings in var.http_listeners : settings.custom_error_pages == null ? true : (
        alltrue([
          for page in settings.custom_error_pages :
          contains(["403", "502"], page.status_code)
        ])
      )
    ])
    error_message = "Invalid status code. Possible values are: 403 and 502."
  }
  validation {
    condition = alltrue([
      for settings in var.http_listeners : settings.custom_error_pages == null ? true : (
        alltrue([
          for page in settings.custom_error_pages :
          startswith(page.custom_error_page_url, "http")
        ])
      )
    ])
    error_message = "Invalid custom error page url. Url must be http or https."
  }
}

variable "request_routing_rules" {
  description = "One or more request routing rules to be used for HTTP listeners."
  type = list(object({
    name                        = string
    priority                    = number
    rule_type                   = string
    http_listener_name          = string
    backend_address_pool_name   = optional(string)
    backend_http_settings_name  = optional(string)
    redirect_configuration_name = optional(string)
    rewrite_rule_set_name       = optional(string)
    url_path_map_name           = optional(string)
  }))
  validation {
    condition = alltrue([
      for rule in var.request_routing_rules :
      contains(["Basic", "PathBasedRouting"], rule.rule_type)
    ])
    error_message = "Invalid rule_type specified. Possible values are: Basic, PathBasedRouting."
  }
  validation {
    condition = alltrue([
      for rule in var.request_routing_rules :
      (rule.backend_address_pool_name == null && rule.backend_http_settings_name == null && rule.redirect_configuration_name != null) ||
      (rule.backend_address_pool_name != null && rule.backend_http_settings_name != null && rule.redirect_configuration_name == null)
    ])
    error_message = "The redirect_configuration_name and backend_http_settings_name + backend_address_pool_name are mutually exclusive and cannot both be set."
  }
}

variable "url_path_maps" {
  description = "List of URL path maps associated to path-based rules."
  type = list(object({
    name                                = string
    default_backend_address_pool_name   = optional(string)
    default_backend_http_settings_name  = optional(string)
    default_redirect_configuration_name = optional(string)
    default_rewrite_rule_set_name       = optional(string)
    path_rules = list(object({
      name                        = string
      paths                       = list(string)
      backend_address_pool_name   = optional(string)
      backend_http_settings_name  = optional(string)
      redirect_configuration_name = optional(string)
      rewrite_rule_set_name       = optional(string)
      firewall_policy_id          = optional(string)
    }))
  }))
  default = []
  validation {
    condition = alltrue([
      for setting in var.url_path_maps : var.url_path_maps == null ? true : (
        (setting.default_backend_address_pool_name != null && setting.default_backend_http_settings_name != null && setting.default_redirect_configuration_name == null) ||
        (setting.default_backend_address_pool_name == null && setting.default_backend_http_settings_name == null && setting.default_redirect_configuration_name != null)
      )
    ])
    error_message = "Both default_backend_address_pool_name and default_backend_http_settings_name or default_redirect_configuration_name should be specified."
  }
  validation {
    condition = alltrue([
      for setting in var.url_path_maps : var.url_path_maps == null ? true : alltrue([
        for rule in setting.path_rules :
        (rule.backend_address_pool_name != null && rule.redirect_configuration_name == null) ||
        (rule.backend_address_pool_name == null)
      ])
    ])
    error_message = "Backend_address_pool_name cannot be set if redirect_configuration_name is set."
  }
  validation {
    condition = alltrue([
      for setting in var.url_path_maps : var.url_path_maps == null ? true : alltrue([
        for rule in setting.path_rules : alltrue([
          for p in rule.paths :
          startswith(p, "/")
        ])
      ])
    ])
    error_message = "Invalid path specified. Must start with: /"
  }
}

variable "redirect_configurations" {
  description = "List of redirects used associated to backend targets on request routing rules."
  type = list(object({
    name                 = string
    redirect_type        = string
    target_listener_name = optional(string)
    target_url           = optional(string)
    include_path         = optional(bool, true)
    include_query_string = optional(bool, true)
  }))
  default = []
  validation {
    condition = var.redirect_configurations == null ? true : (
      alltrue([
        for conf in var.redirect_configurations :
        contains(["Permanent", "Temporary", "Found", "SeeOther"], conf.redirect_type)
      ])
    )
    error_message = "Invalid redirect type specified. Possible values are: Permanent, Temporary, Found and SeeOther."
  }
  validation {
    condition = var.redirect_configurations == null ? true : (
      alltrue([
        for conf in var.redirect_configurations :
        (conf.target_listener_name != null && conf.target_url == null) ||
        (conf.target_listener_name == null && conf.target_url != null)
      ])
    )
    error_message = "Either specify the target listener name or the target url."
  }
}

variable "rewrite_rule_sets" {
  description = "List of rewrite rule sets."
  type = list(object({
    name = string
    rewrite_rules = optional(list(object({
      name          = string
      rule_sequence = number
      conditions = optional(list(object({
        variable    = string
        pattern     = string
        ignore_case = optional(bool, false)
        negate      = optional(bool, false)
      })), [])
      request_header_configurations = optional(list(object({
        header_name  = string
        header_value = string
      })), [])
      response_header_configurations = optional(list(object({
        header_name  = string
        header_value = string
      })), [])
      url = optional(list(object({
        path         = optional(string)
        query_string = optional(string)
        components   = optional(string)
        reroute      = optional(bool, false)
      })), [])
    })))
  }))
  default = []
}

variable "authentication_certificates" {
  description = "Authentication certificates for usage by the backends."
  type = list(object({
    name = string
    data = string
  }))
  default = []
}

variable "trusted_root_certificates" {
  description = "Trusted root certificates for usage by the backends."
  type = list(object({
    name                = string
    data                = optional(string)
    key_vault_secret_id = optional(string)
  }))
  default = []
  validation {
    condition = alltrue([
      for cert in var.trusted_root_certificates : var.trusted_root_certificates == null ? true : (
        (cert.data == null && cert.key_vault_secret_id != null) ||
        (cert.data != null && cert.key_vault_secret_id == null)
      )
    ])
    error_message = "Either specify a PFX file using data, or specify a KeyVault secret ID, not both."
  }
}

variable "ssl_policy" {
  description = "The default ssl policy for the application gateway."
  type = object({
    policy_type          = string
    policy_name          = optional(string)
    cipher_suites        = optional(list(string))
    min_protocol_version = optional(string)
  })
  default = {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101"
  }
  validation {
    condition     = contains(["Predefined", "Custom", "CustomV2"], var.ssl_policy.policy_type)
    error_message = "Invalid policy type specified. Possible values are: Predefined, Custom and CustomV2."
  }
  validation {
    condition = var.ssl_policy.policy_type != "Predefined" ? true : (
      var.ssl_policy.policy_name != null
    )
    error_message = "Policy name must be set when policy type is set to Predefined."
  }
  validation {
    condition = var.ssl_policy.cipher_suites == null ? true : (
      var.ssl_policy.policy_type == "Custom" || var.ssl_policy.policy_type == "CustomV2"
    )
    error_message = "Policy type must be set to Custom or CustomV2 when configuring cipher suites."
  }
  validation {
    condition = var.ssl_policy.min_protocol_version == null ? true : (
      (contains(["TLSv1_0", "TLSv1_1", "TLSv1_2"], var.ssl_policy.min_protocol_version) && var.ssl_policy.policy_type == "Custom") ||
      (contains(["TLSv1_2", "TLSv1_3"], var.ssl_policy.min_protocol_version) && var.ssl_policy.policy_type == "CustomV2")
    )
    error_message = <<EOH
     Invalid TLS verion specified. Possible values are:

     Custom: TLSv1_0, TLSv1_1 and TLSv1_2.
     CustomV2: TLSv1_2 and TLSv1_3

    EOH
  }
}

variable "ssl_profiles" {
  description = "One or more SSL profiles for usage by HTTPS listeners."
  type = list(object({
    name                                 = string
    trusted_client_certificate_names     = optional(list(string))
    verify_client_cert_issuer_dn         = optional(bool, false)
    verify_client_certificate_revocation = optional(string)
    ssl_policy = optional(object({
      policy_type          = optional(string)
      policy_name          = optional(string)
      cipher_suites        = optional(list(string))
      min_protocol_version = optional(string)
    }))
  }))
  default = []
  validation {
    condition = alltrue([
      for profile in var.ssl_profiles : profile.verify_client_certificate_revocation == null ? true : (
        contains(["OCSP"], profile.verify_client_certificate_revocation)
      )
    ])
    error_message = "Invalid client certificate revocation status method. Possible values: OCSP."
  }
  validation {
    condition = alltrue([
      for profile in var.ssl_profiles : profile.ssl_policy == null ? true : (
        profile.ssl_policy.policy_type == null ? true : (
          contains(["Predefined", "Custom", "CustomV2"], profile.ssl_policy.policy_type)
        )
      )
    ])
    error_message = "Invalid policy type specified. Possible values are: Predefined, Custom and CustomV2."
  }
  validation {
    condition = alltrue([
      for profile in var.ssl_profiles : profile.ssl_policy == null ? true : (
        profile.ssl_policy.policy_name == null ? true : (
          profile.ssl_policy.policy_name != null && profile.ssl_policy.policy_type == "Predefined"
        )
      )
    ])
    error_message = "Policy type must be set to Predefined when configuring a policy name."
  }
  validation {
    condition = alltrue([
      for profile in var.ssl_profiles : profile.ssl_policy == null ? true : (
        profile.ssl_policy.cipher_suites == null ? true : (
          profile.ssl_policy.policy_type == "Custom" || profile.ssl_policy.policy_type == "CustomV2"
        )
      )
    ])
    error_message = "Policy type must be set to Custom or CustomV2 when configuring cipher suites."
  }
  validation {
    condition = alltrue([
      for profile in var.ssl_profiles : profile.ssl_policy == null ? true : (
        profile.ssl_policy.min_protocol_version == null ? true : (
          (contains(["TLSv1_0", "TLSv1_1", "TLSv1_2"], profile.ssl_policy.min_protocol_version) && profile.ssl_policy.policy_type == "Custom") ||
          (contains(["TLSv1_2", "TLSv1_3"], profile.ssl_policy.min_protocol_version) && profile.ssl_policy.policy_type == "CustomV2")
        )
      )
    ])
    error_message = <<EOH
     Invalid TLS verion specified. Possible values are:

     Custom: TLSv1_0, TLSv1_1 and TLSv1_2.
     CustomV2: TLSv1_2 and TLSv1_3

    EOH
  }
}

variable "trusted_client_certificates" {
  description = "Trusted client certificates for usage by the ssl profiles."
  type = list(object({
    name = string
    data = optional(string)
  }))
  default = []
}

variable "health_probes" {
  description = "Health probes for usage by the backends."
  type = list(object({
    name                                      = string
    protocol                                  = string
    pick_host_name_from_backend_http_settings = optional(bool, false)
    host                                      = optional(string)
    port                                      = optional(number)
    path                                      = string
    interval                                  = optional(number, 30)
    timeout                                   = optional(number, 30)
    unhealthy_threshold                       = optional(number, 3)
    matching_conditions = optional(object({
      body        = string
      status_code = list(string)
    }))
  }))
  default = []
  validation {
    condition = alltrue([
      for probe in var.health_probes :
      contains(["Http", "Https"], probe.protocol)
    ])
    error_message = "Invalid protocol. Possible values are: Http and Https."
  }
  validation {
    condition = alltrue([
      for probe in var.health_probes : var.health_probes == null ? true : (
        (probe.host != null && probe.pick_host_name_from_backend_http_settings != true) ||
        (probe.host == null && probe.pick_host_name_from_backend_http_settings == true)
      )
    ])
    error_message = "Either host or pick_host_name_from_backend_http_settings must be set."
  }
  validation {
    condition = alltrue([
      for probe in var.health_probes : var.health_probes == null ? true : (
        probe.port == null ? true : (
          probe.port >= 1 && probe.port <= 65535
        )
      )
    ])
    error_message = "Invalid port number. Number must be between 1 and 65535."
  }
  validation {
    condition = alltrue([
      for probe in var.health_probes : var.health_probes == null ? true : (
        startswith(probe.path, "/")
      )
    ])
    error_message = "Invalid path specified. Must start with: /"
  }
  validation {
    condition = alltrue([
      for probe in var.health_probes : var.health_probes == null ? true : (
        probe.interval >= 1 && probe.interval <= 86400
      )
    ])
    error_message = "Invalid interval specified. Number must be between 1 and 86400 seconds."
  }
  validation {
    condition = alltrue([
      for probe in var.health_probes : var.health_probes == null ? true : (
        probe.timeout >= 1 && probe.timeout <= 86400
      )
    ])
    error_message = "Invalid timeout specified. Number must be between 1 and 86400 seconds."
  }
  validation {
    condition = alltrue([
      for probe in var.health_probes : var.health_probes == null ? true : (
        probe.unhealthy_threshold >= 1 && probe.unhealthy_threshold <= 20
      )
    ])
    error_message = "Invalid unhealthy threshold specified. Number must be between 1 and 20."
  }
}

variable "waf_configuration" {
  description = "The configuration of the web application firewall (WAF). Only used when SKU tier is set to WAF_v2."
  type = object({
    enabled                  = optional(bool, true)
    firewall_mode            = optional(string, "Prevention")
    rule_set_type            = optional(string, "OWASP")
    rule_set_version         = optional(string, "3.1")
    file_upload_limit_mb     = optional(number, 100)
    request_body_check       = optional(bool, true)
    max_request_body_size_kb = optional(number, 128)
    disabled_rule_groups = optional(list(object({
      rule_group_name = string
      rules           = optional(list(string))
    })), [])
    exclusions = optional(list(object({
      match_variable          = string
      selector_match_operator = optional(string)
      selector                = optional(string)
    })), [])
  })
  validation {
    condition     = contains(["Detection", "Prevention"], var.waf_configuration.firewall_mode)
    error_message = "Invalid firewall_mode specified. Possible values are: Detection, Prevention."
  }
  validation {
    condition     = contains(["OWASP", "Microsoft_BotManagerRuleSet", "Microsoft_DefaultRuleSet"], var.waf_configuration.rule_set_type)
    error_message = "Invalid rule set type specified. Possible values are: OWASP, Microsoft_BotManagerRuleSet and Microsoft_DefaultRuleSet. Defaults to OWASP."
  }
  validation {
    condition     = contains(["0.1", "1.0", "2.1", "2.2.9", "3.0", "3.1", "3.2"], var.waf_configuration.rule_set_version)
    error_message = "Invalid rule set version specified. Possible values are: 0.1, 1.0, 2.1, 2.2.9, 3.0, 3.1 and 3.2."
  }
  validation {
    condition = (
      (var.waf_configuration.file_upload_limit_mb >= 1 && var.waf_configuration.file_upload_limit_mb <= 750)
    )
    error_message = "Invalid file upload limit (MB) specified. Number must be between 1 and 750 MB for WAF_v2 SKU and between 1 and 500 MB for other SKU's."
  }
  validation {
    condition = (
      (var.waf_configuration.max_request_body_size_kb >= 1 && var.waf_configuration.max_request_body_size_kb <= 128)
    )
    error_message = "Invalid max request body size (KB) specified. Number must be between 1 and 128 KB."
  }
  validation {
    condition = var.waf_configuration.exclusions == null ? true : (
      alltrue([
        for exclusion in var.waf_configuration.exclusions :
        contains(["RequestArgNames", "RequestCookieNames", "RequestHeaderNames"], exclusion.match_variable)
      ])
    )
    error_message = "Invalid match variable value specified. Possible values are: RequestArgNames, RequestCookieNames and RequestHeaderNames."
  }
  validation {
    condition = var.waf_configuration.exclusions == null ? true : (
      alltrue([
        for exclusion in var.waf_configuration.exclusions : exclusion.selector_match_operator == null ? true : (
          contains(["Contains", "EndsWith", "Equals", "EqualsAny", "StartsWith"], exclusion.selector_match_operator)
        )
      ])
    )
    error_message = "Invalid selector match operator value specified. Possible values are: Contains, EndsWith, Equals, EqualsAny and StartsWith."
  }
  validation {
    condition = var.waf_configuration.exclusions == null ? true : (
      alltrue([
        for exclusion in var.waf_configuration.exclusions :
        (exclusion.selector_match_operator == null && exclusion.selector == null) ||
        (exclusion.selector_match_operator != null && exclusion.selector != null)
      ])
    )
    error_message = "Selector match operator and selector must both be specified."
  }
  default = {
    enabled                  = true
    firewall_mode            = "Prevention"
    rule_set_version         = "3.1"
    rule_set_type            = "OWASP"
    file_upload_limit_mb     = 100
    request_body_check       = true
    max_request_body_size_kb = 128
  }
}

variable "log_retention_in_days" {
  description = "The retention in days for the log analytic workspace."
  type        = number
  default     = 90
  validation {
    condition     = var.log_retention_in_days >= 30 && var.log_retention_in_days <= 730
    error_message = "Invalid retention in days value. Number should be between 30 and 730."
  }
}
