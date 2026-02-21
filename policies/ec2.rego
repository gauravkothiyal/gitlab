# EC2 / ASG Policies — IL5 GovCloud Compliance
#
# References:
#   NIST 800-53 SC-28  — Protection of Information at Rest
#   NIST 800-53 IA-2   — Identification and Authentication
#   NIST 800-53 AC-17  — Remote Access
#   NIST 800-53 AC-3   — Access Enforcement
#   NIST 800-53 SC-7   — Boundary Protection

package terraform.ec2

import data.terraform.exceptions
import rego.v1

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
ec2_instances contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_instance"
	rc.change.actions[_] in ["create", "update"]
}

launch_templates contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_launch_template"
	rc.change.actions[_] in ["create", "update"]
}

security_groups contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_security_group"
	rc.change.actions[_] in ["create", "update"]
}

sg_rules contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_security_group_rule"
	rc.change.actions[_] in ["create", "update"]
}

# -------------------------------------------------------
# SC-28: Require all EBS volumes to be encrypted with KMS
# -------------------------------------------------------
deny contains msg if {
	some rc in ec2_instances
	root := rc.change.after.root_block_device[_]
	not root.encrypted
	not exceptions.is_excepted("require_ebs_encryption", rc.address)
	msg := sprintf(
		"EC2 root_block_device must be encrypted [SC-28] (%s)",
		[rc.address],
	)
}

deny contains msg if {
	some rc in ec2_instances
	ebs := rc.change.after.ebs_block_device[_]
	not ebs.encrypted
	not exceptions.is_excepted("require_ebs_encryption", rc.address)
	msg := sprintf(
		"EC2 ebs_block_device '%s' must be encrypted [SC-28] (%s)",
		[ebs.device_name, rc.address],
	)
}

deny contains msg if {
	some rc in ec2_instances
	root := rc.change.after.root_block_device[_]
	root.encrypted
	not root.kms_key_id
	not exceptions.is_excepted("require_ebs_kms_key", rc.address)
	msg := sprintf(
		"EC2 root_block_device must specify a KMS key [SC-28] (%s)",
		[rc.address],
	)
}

deny contains msg if {
	some rc in ec2_instances
	ebs := rc.change.after.ebs_block_device[_]
	ebs.encrypted
	not ebs.kms_key_id
	not exceptions.is_excepted("require_ebs_kms_key", rc.address)
	msg := sprintf(
		"EC2 ebs_block_device '%s' must specify a KMS key [SC-28] (%s)",
		[ebs.device_name, rc.address],
	)
}

# Same for launch templates
deny contains msg if {
	some rc in launch_templates
	bd := rc.change.after.block_device_mappings[_]
	ebs := bd.ebs
	not ebs.encrypted
	not exceptions.is_excepted("require_ebs_encryption", rc.address)
	msg := sprintf(
		"Launch template EBS must be encrypted [SC-28] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# IA-2: Require IMDSv2 (http_tokens = "required")
#        Prevents SSRF-based credential theft
# -------------------------------------------------------
deny contains msg if {
	some rc in ec2_instances
	metadata := rc.change.after.metadata_options
	some opt in metadata
	opt.http_tokens != "required"
	not exceptions.is_excepted("require_imdsv2", rc.address)
	msg := sprintf(
		"EC2 instance must require IMDSv2 (http_tokens = required) [IA-2] (%s)",
		[rc.address],
	)
}

deny contains msg if {
	some rc in ec2_instances
	not rc.change.after.metadata_options
	not exceptions.is_excepted("require_imdsv2", rc.address)
	msg := sprintf(
		"EC2 instance must set metadata_options with http_tokens = required [IA-2] (%s)",
		[rc.address],
	)
}

deny contains msg if {
	some rc in launch_templates
	metadata := rc.change.after.metadata_options
	some opt in metadata
	opt.http_tokens != "required"
	not exceptions.is_excepted("require_imdsv2", rc.address)
	msg := sprintf(
		"Launch template must require IMDSv2 (http_tokens = required) [IA-2] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# IA-2: Require instance profile (IAM role, no hardcoded keys)
# -------------------------------------------------------
deny contains msg if {
	some rc in ec2_instances
	not rc.change.after.iam_instance_profile
	not exceptions.is_excepted("require_instance_profile", rc.address)
	msg := sprintf(
		"EC2 instance must have an IAM instance profile [IA-2] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# AC-17: Require SSH key pair
# -------------------------------------------------------
deny contains msg if {
	some rc in ec2_instances
	not rc.change.after.key_name
	not exceptions.is_excepted("require_key_pair", rc.address)
	msg := sprintf(
		"EC2 instance must have a key_name for SSH access [AC-17] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# AC-3: Block public IPs on instances
# -------------------------------------------------------
deny contains msg if {
	some rc in ec2_instances
	rc.change.after.associate_public_ip_address
	not exceptions.is_excepted("deny_public_ip", rc.address)
	msg := sprintf(
		"EC2 instance must not have a public IP [AC-3] (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# AC-3: Require API termination protection
# -------------------------------------------------------
warn contains msg if {
	some rc in ec2_instances
	not rc.change.after.disable_api_termination
	not exceptions.is_excepted("require_termination_protection", rc.address)
	msg := sprintf(
		"EC2 instance should have disable_api_termination = true (%s)",
		[rc.address],
	)
}

# -------------------------------------------------------
# SC-7: Security group — no unrestricted ingress on
#        sensitive ports (SSH 22, RDP 3389, DB 5432/3306)
# -------------------------------------------------------
_sensitive_ports := {22, 3389, 5432, 3306}

deny contains msg if {
	some rc in security_groups
	some rule in rc.change.after.ingress
	rule.from_port <= port
	rule.to_port >= port
	some port in _sensitive_ports
	some cidr in rule.cidr_blocks
	cidr == "0.0.0.0/0"
	not exceptions.is_excepted("deny_open_sensitive_ports", rc.address)
	msg := sprintf(
		"Security group allows 0.0.0.0/0 on port %d [SC-7] (%s)",
		[port, rc.address],
	)
}

deny contains msg if {
	some rc in sg_rules
	rc.change.after.type == "ingress"
	rc.change.after.from_port <= port
	rc.change.after.to_port >= port
	some port in _sensitive_ports
	some cidr in rc.change.after.cidr_blocks
	cidr == "0.0.0.0/0"
	not exceptions.is_excepted("deny_open_sensitive_ports", rc.address)
	msg := sprintf(
		"Security group rule allows 0.0.0.0/0 on port %d [SC-7] (%s)",
		[port, rc.address],
	)
}

# Block any ingress rule that opens ALL ports to 0.0.0.0/0
deny contains msg if {
	some rc in security_groups
	some rule in rc.change.after.ingress
	rule.from_port == 0
	rule.to_port == 0
	rule.protocol == "-1"
	some cidr in rule.cidr_blocks
	cidr == "0.0.0.0/0"
	not exceptions.is_excepted("deny_open_all_ports", rc.address)
	msg := sprintf(
		"Security group allows all traffic from 0.0.0.0/0 [SC-7] (%s)",
		[rc.address],
	)
}
