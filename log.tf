# create log analytics workspace for application gateway diagnostics
resource "azurerm_log_analytics_workspace" "this" {
  name                = "${local.prefix}-log-agw-${local.suffix}-${var.instance}"
  location            = var.general.location
  resource_group_name = var.general.resource_group.name
  tags                = var.tags
  retention_in_days   = var.log_retention_in_days

  lifecycle {
    ignore_changes = [tags]
  }
}

# configure diagnostic settings for application gateway
resource "azurerm_monitor_diagnostic_setting" "this" {
  name                           = "application gateway logs"
  target_resource_id             = azurerm_application_gateway.this.id
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category_group = "allLogs"
  }

  metric {
    category = "AllMetrics"
  }
}
