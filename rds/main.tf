resource "null_resource" "rds_placeholder" {
  triggers = {
    environment = var.environment
  }
}
