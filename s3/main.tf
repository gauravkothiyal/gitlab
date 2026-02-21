resource "null_resource" "s3_placeholder" {
  triggers = {
    environment = var.environment
  }
}
