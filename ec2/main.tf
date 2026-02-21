resource "null_resource" "ec2_placeholder" {
  triggers = {
    environment = var.environment
  }
}
