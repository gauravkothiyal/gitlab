# General Policies — Compliance
#
# These are org-specific rules that Checkov/Trivy CANNOT enforce:
#   - Required tags for asset inventory
#   - Region restriction to us-east-1
#   - Naming conventions
#
# References:
#   NIST 800-53 CM-8  — Information System Component Inventory
#   NIST 800-53 AC-2  — Account Management (ownership)
#   NIST 800-53 PE-18 — Location of Information System Components

package terraform.general

import data.terraform.exceptions
import rego.v1

# -------------------------------------------------------
# Tag-able resource types in the plan
# -------------------------------------------------------
_taggable_types := {
	"aws_instance",
	"aws_db_instance",
	"aws_s3_bucket",
	"aws_security_group",
	"aws_launch_template",
	"aws_autoscaling_group",
	"aws_ebs_volume",
	"aws_eip",
	"aws_lb",
	"aws_lb_target_group",
}

taggable_resources contains rc if {
	some rc in input.resource_changes
	rc.type in _taggable_types
	rc.change.actions[_] in ["create", "update"]
}

# -------------------------------------------------------
# CM-8: Require mandatory tags: Name, Owner, Environment
# -------------------------------------------------------
_required_tags := {"Name", "Owner", "Environment"}

deny contains msg if {
	some rc in taggable_resources
	tags := object.get(rc.change.after, "tags", {})
	some required_tag in _required_tags
	not tags[required_tag]
	not exceptions.is_excepted("require_tags", rc.address)
	msg := sprintf(
		"Resource missing required tag '%s' [CM-8] (%s)",
		[required_tag, rc.address],
	)
}

# Catch resources with null/empty tags
deny contains msg if {
	some rc in taggable_resources
	not rc.change.after.tags
	some required_tag in _required_tags
	not exceptions.is_excepted("require_tags", rc.address)
	msg := sprintf(
		"Resource has no tags, missing '%s' [CM-8] (%s)",
		[required_tag, rc.address],
	)
}

# -------------------------------------------------------
# PE-18: Restrict to us-east-1 only
#
# Checks the provider config region in the plan.
# Also catches any resource that explicitly sets a region.
# -------------------------------------------------------
_allowed_regions := {"us-east-1"}

deny contains msg if {
	some rc in input.resource_changes
	rc.change.actions[_] in ["create", "update"]
	region := object.get(rc.change.after, "region", "")
	region != ""
	not region in _allowed_regions
	not exceptions.is_excepted("require_region", rc.address)
	msg := sprintf(
		"Resource deployed in '%s', must be in %v [PE-18] (%s)",
		[region, _allowed_regions, rc.address],
	)
}

# Check provider configuration region
deny contains msg if {
	some name, config in input.configuration.provider_config
	startswith(name, "aws")
	region := config.expressions.region.constant_value
	not region in _allowed_regions
	not exceptions.is_excepted("require_region", name)
	msg := sprintf(
		"Provider '%s' configured for region '%s', must be in %v [PE-18]",
		[name, region, _allowed_regions],
	)
}

# -------------------------------------------------------
# Naming convention: resources should use the bmc3 prefix
# -------------------------------------------------------
warn contains msg if {
	some rc in taggable_resources
	tags := object.get(rc.change.after, "tags", {})
	name := tags.Name
	not startswith(name, "bmc3-")
	msg := sprintf(
		"Resource Name tag '%s' should start with 'bmc3-' (%s)",
		[name, rc.address],
	)
}
