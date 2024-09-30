locals {
  location_table = {
    westeurope  = "westeu"
    northeurope = "northeu"
  }
  prefix = lower(var.general.prefix)
  suffix = lower("${var.general.application}-${var.general.environment}-${local.location_table[var.general.location]}")
}
