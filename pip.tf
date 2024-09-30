# create public ip for the application gateway
resource "azurerm_public_ip" "this" {
  name                = "${local.prefix}-pip-agw-${local.suffix}-${var.instance}"
  location            = var.general.location
  resource_group_name = var.general.resource_group.name
  tags                = var.tags
  sku                 = "Standard"
  sku_tier            = "Regional"
  allocation_method   = "Static"
  zones               = var.availability_zones != null ? [1, 2, 3] : null # quals to zone redundant

  lifecycle {
    ignore_changes = [tags]
  }
}
