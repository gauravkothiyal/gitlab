# S3 Bucket Policies — IL5 GovCloud Compliance
#
# Conftest evaluates the Terraform plan JSON.
# Resource changes are under input.resource_changes[].change.after
#
# References:
#   NIST 800-53 SC-28  — Protection of Information at Rest
#   NIST 800-53 AC-3   — Access Enforcement
#   NIST 800-53 AU-3   — Content of Audit Records (logging)

package terraform.s3

import data.terraform.exceptions
import rego.v1

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
s3_buckets contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	rc.change.actions[_] in ["create", "update"]
}

s3_bucket_configs(config_type) := {rc |
	some rc in input.resource_changes
	rc.type == config_type
	rc.change.actions[_] in ["create", "update"]
}

# -------------------------------------------------------
# SC-28: Require server-side encryption (SSE-KMS preferred)
# -------------------------------------------------------
deny contains msg if {
	some rc in s3_bucket_configs("aws_s3_bucket_server_side_encryption_configuration")
	rules := rc.change.after.rule
	some rule in rules
	sse := rule.apply_server_side_encryption_by_default
	sse.sse_algorithm != "aws:kms"
	not exceptions.is_excepted("require_s3_kms_encryption", rc.address)
	msg := sprintf(
		"S3 bucket encryption must use aws:kms, got '%s' [SC-28] (%s)",
		[sse.sse_algorithm, rc.address],
	)
}

# If no encryption config resource exists for a bucket, flag it
deny contains msg if {
	count(s3_buckets) > 0
	count(s3_bucket_configs("aws_s3_bucket_server_side_encryption_configuration")) == 0
	not exceptions.is_excepted("require_s3_encryption", "*")
	msg := "S3 buckets must have server-side encryption configured [SC-28]"
}

# -------------------------------------------------------
# AC-3: Block public access — require public access block
# -------------------------------------------------------
deny contains msg if {
	some rc in s3_bucket_configs("aws_s3_bucket_public_access_block")
	after := rc.change.after
	not after.block_public_acls
	not exceptions.is_excepted("require_public_access_block", rc.address)
	msg := sprintf(
		"S3 bucket must block public ACLs [AC-3] (%s)",
		[rc.address],
	)
}

deny contains msg if {
	some rc in s3_bucket_configs("aws_s3_bucket_public_access_block")
	after := rc.change.after
	not after.block_public_policy
	not exceptions.is_excepted("require_public_access_block", rc.address)
	msg := sprintf(
		"S3 bucket must block public policy [AC-3] (%s)",
		[rc.address],
	)
}

deny contains msg if {
	some rc in s3_bucket_configs("aws_s3_bucket_public_access_block")
	after := rc.change.after
	not after.ignore_public_acls
	not exceptions.is_excepted("require_public_access_block", rc.address)
	msg := sprintf(
		"S3 bucket must ignore public ACLs [AC-3] (%s)",
		[rc.address],
	)
}

deny contains msg if {
	some rc in s3_bucket_configs("aws_s3_bucket_public_access_block")
	after := rc.change.after
	not after.restrict_public_buckets
	not exceptions.is_excepted("require_public_access_block", rc.address)
	msg := sprintf(
		"S3 bucket must restrict public buckets [AC-3] (%s)",
		[rc.address],
	)
}

# If no public access block exists at all, deny
deny contains msg if {
	count(s3_buckets) > 0
	count(s3_bucket_configs("aws_s3_bucket_public_access_block")) == 0
	not exceptions.is_excepted("require_public_access_block", "*")
	msg := "S3 buckets must have a public access block resource [AC-3]"
}

# -------------------------------------------------------
# CP-9: Require versioning on buckets
# -------------------------------------------------------
deny contains msg if {
	some rc in s3_bucket_configs("aws_s3_bucket_versioning")
	config := rc.change.after.versioning_configuration
	some vc in config
	vc.status != "Enabled"
	not exceptions.is_excepted("require_s3_versioning", rc.address)
	msg := sprintf(
		"S3 bucket versioning must be Enabled [CP-9] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# AU-3: Require bucket logging
# -------------------------------------------------------
warn contains msg if {
	count(s3_buckets) > 0
	count(s3_bucket_configs("aws_s3_bucket_logging")) == 0
	not exceptions.is_excepted("require_s3_logging", "*")
	msg := "S3 buckets should have access logging configured [AU-3]"
}
