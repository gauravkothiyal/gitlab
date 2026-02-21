# RDS Policies — IL5 GovCloud Compliance
#
# References:
#   NIST 800-53 SC-28  — Protection of Information at Rest
#   NIST 800-53 SC-8   — Transmission Confidentiality and Integrity
#   NIST 800-53 CP-9   — Information System Backup
#   NIST 800-53 CP-10  — System Recovery and Reconstitution
#   NIST 800-53 SI-2   — Flaw Remediation (minor version upgrades)

package terraform.rds

import data.terraform.exceptions
import rego.v1

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
rds_instances contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_db_instance"
	rc.change.actions[_] in ["create", "update"]
}

rds_param_groups contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_db_parameter_group"
	rc.change.actions[_] in ["create", "update"]
}

# -------------------------------------------------------
# SC-28: Require encryption at rest with KMS
# -------------------------------------------------------
deny contains msg if {
	some rc in rds_instances
	not rc.change.after.storage_encrypted
	not exceptions.is_excepted("require_rds_encryption", rc.address)
	msg := sprintf(
		"RDS instance must have storage_encrypted = true [SC-28] (%s)",
		[rc.address],
	)
}

deny contains msg if {
	some rc in rds_instances
	rc.change.after.storage_encrypted
	not rc.change.after.kms_key_id
	not exceptions.is_excepted("require_rds_kms_key", rc.address)
	msg := sprintf(
		"RDS instance must specify a KMS key for encryption [SC-28] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# AC-3: Block public accessibility
# -------------------------------------------------------
deny contains msg if {
	some rc in rds_instances
	rc.change.after.publicly_accessible
	not exceptions.is_excepted("deny_rds_public_access", rc.address)
	msg := sprintf(
		"RDS instance must not be publicly accessible [AC-3] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# SC-8: Require deletion protection
# -------------------------------------------------------
deny contains msg if {
	some rc in rds_instances
	not rc.change.after.deletion_protection
	not exceptions.is_excepted("require_rds_deletion_protection", rc.address)
	msg := sprintf(
		"RDS instance must have deletion_protection = true (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# CP-9: Require backup retention >= 7 days
# -------------------------------------------------------
deny contains msg if {
	some rc in rds_instances
	rc.change.after.backup_retention_period < 7
	not exceptions.is_excepted("require_rds_backup_retention", rc.address)
	msg := sprintf(
		"RDS backup_retention_period must be >= 7 days, got %d [CP-9] (%s)",
		[rc.change.after.backup_retention_period, rc.address],
	)
}

# -------------------------------------------------------
# CP-10: Require multi-AZ for production (dsop)
# -------------------------------------------------------
deny contains msg if {
	some rc in rds_instances
	# Check if any tag indicates dsop/production environment
	tags := rc.change.after.tags
	tags.Environment == "dsop"
	not rc.change.after.multi_az
	not exceptions.is_excepted("require_rds_multi_az", rc.address)
	msg := sprintf(
		"RDS instance in dsop must have multi_az = true [CP-10] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# SI-2: Require auto minor version upgrade
# -------------------------------------------------------
warn contains msg if {
	some rc in rds_instances
	not rc.change.after.auto_minor_version_upgrade
	not exceptions.is_excepted("require_rds_auto_upgrade", rc.address)
	msg := sprintf(
		"RDS instance should have auto_minor_version_upgrade = true [SI-2] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# SC-8: Require force_ssl via parameter group
#        (Postgres: rds.force_ssl = 1)
# -------------------------------------------------------
warn contains msg if {
	some rc in rds_param_groups
	params := rc.change.after.parameter
	not _has_force_ssl(params)
	not exceptions.is_excepted("require_rds_force_ssl", rc.address)
	msg := sprintf(
		"RDS parameter group should set rds.force_ssl = 1 [SC-8] (%s)",
		[rc.address],
	)
}

_has_force_ssl(params) if {
	some p in params
	p.name == "rds.force_ssl"
	p.value == "1"
}
