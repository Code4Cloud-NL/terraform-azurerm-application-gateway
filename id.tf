# create user-assigned managed identity (e.g. to assign permissions on key vault)
resource "azurerm_user_assigned_identity" "this" {
  name                = "${local.prefix}-id-agw-${local.suffix}-${var.instance}"
  location            = var.general.location
  resource_group_name = var.general.resource_group.name
  tags                = var.tags

  lifecycle {
    ignore_changes = [tags]
  }
}
