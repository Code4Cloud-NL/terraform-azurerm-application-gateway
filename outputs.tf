output "application_gateway_id" {
  description = "The ID of the application gateway."
  value       = azurerm_application_gateway.this.id
}

output "frontend_ip_configuration_ids" {
  description = "The ID's of the frontend ip configuration."
  value       = azurerm_application_gateway.this.frontend_ip_configuration[*].id
}

output "frontend_port_ids" {
  description = "The ID's of the frontend ports."
  value       = azurerm_application_gateway.this.frontend_port[*].id
}

output "gateway_ip_configuration_ids" {
  description = "The ID's of the application gateway ip configuration."
  value       = azurerm_application_gateway.this.gateway_ip_configuration[*].id
}

output "backend_address_pool_ids" {
  description = "The ID's of the backend address pools."
  value       = azurerm_application_gateway.this.backend_address_pool[*].id
}

output "backend_http_settings_ids" {
  description = "The ID's of the backend http settings."
  value       = azurerm_application_gateway.this.backend_http_settings[*].id
}

output "ssl_profile_ids" {
  description = "The ID's of the ssl profiles."
  value       = azurerm_application_gateway.this.ssl_profile[*].id
}

output "http_listener_ids" {
  description = "The ID's of the http listeners."
  value       = azurerm_application_gateway.this.http_listener[*].id
}

output "http_listener_ssl_certificate_ids" {
  description = "The ID's of the associated ssl certificates."
  value       = azurerm_application_gateway.this.http_listener[*].ssl_certificate_id
}

output "ssl_certificate_ids" {
  description = "The ID's of the ssl certificates."
  value       = azurerm_application_gateway.this.ssl_certificate[*].id
}

output "request_routing_rule_ids" {
  description = "The ID's of the request routing rules."
  value       = azurerm_application_gateway.this.request_routing_rule[*].id
}

output "rewrite_rule_set_ids" {
  description = "The ID's of the rewrite rule sets."
  value       = azurerm_application_gateway.this.rewrite_rule_set[*].id
}

output "health_probe_ids" {
  description = "The ID's of the health probes."
  value       = azurerm_application_gateway.this.probe[*].id
}

output "log_analytic_workspace-id" {
  description = "The ID of the log analytic workspace."
  value       = azurerm_log_analytics_workspace.this.id
}

output "public_ip_id" {
  description = "The ID of the public ip address."
  value       = azurerm_public_ip.this.id
}
