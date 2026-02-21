# Global TFLint Configuration
# These rules are disabled across all environments and components.
# Add project-specific overrides in environments/{env}/{region}/{component}/.tflint.hcl
#
# Find rules: https://github.com/terraform-linters/tflint-ruleset-aws

# -------------------------------------------------------
# Enable the AWS plugin (pre-installed in Docker image)
# -------------------------------------------------------
plugin "aws" {
  enabled = true
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# Example: disable specific rules globally
# rule "aws_s3_bucket_invalid_lifecycle_rule" {
#   enabled = false
# }

# rule "aws_instance_invalid_type" {
#   enabled = false
# }
