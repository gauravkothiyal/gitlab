# Policy Exception Helpers
#
# Shared helper rules used by all policy packages to check whether a
# specific rule + resource combination has been granted an exception
# via the global or environment-level policy-exceptions.json files.
#
# Exception data is loaded via conftest --data flags and appears as:
#   data.global_exceptions[_]   — project-wide exceptions
#   data.env_exceptions[_]      — environment-specific exceptions
#
# Each exception entry has:
#   rule        — the rule name to skip (must match exactly)
#   resource    — the Terraform resource address, or "*" for all
#   reason      — why this exception exists
#   approved_by — who approved it
#   expires     — ISO date (YYYY-MM-DD) when the exception expires

package terraform.exceptions

import rego.v1

# -------------------------------------------------------
# is_excepted: returns true if the given rule + resource
# has a valid (non-expired) exception
# -------------------------------------------------------

# Global wildcard exception (resource = "*")
is_excepted(rule_name, _resource_address) if {
	some ex in data.global_exceptions
	ex.rule == rule_name
	ex.resource == "*"
	_not_expired(ex)
}

# Global exception for a specific resource
is_excepted(rule_name, resource_address) if {
	some ex in data.global_exceptions
	ex.rule == rule_name
	ex.resource == resource_address
	_not_expired(ex)
}

# Environment-level wildcard exception
is_excepted(rule_name, _resource_address) if {
	some ex in data.env_exceptions
	ex.rule == rule_name
	ex.resource == "*"
	_not_expired(ex)
}

# Environment-level exception for a specific resource
is_excepted(rule_name, resource_address) if {
	some ex in data.env_exceptions
	ex.rule == rule_name
	ex.resource == resource_address
	_not_expired(ex)
}

# -------------------------------------------------------
# Expiration check — rejects exceptions past their date
# -------------------------------------------------------
_not_expired(ex) if {
	expiry_ns := time.parse_rfc3339_ns(sprintf("%sT23:59:59Z", [ex.expires]))
	time.now_ns() <= expiry_ns
}

# -------------------------------------------------------
# Warn on expired exceptions so teams know to clean up
# -------------------------------------------------------
warn contains msg if {
	some ex in data.global_exceptions
	not _not_expired(ex)
	msg := sprintf(
		"Global exception expired: rule '%s' for resource '%s' expired on %s (approved by %s)",
		[ex.rule, ex.resource, ex.expires, ex.approved_by],
	)
}

warn contains msg if {
	some ex in data.env_exceptions
	not _not_expired(ex)
	msg := sprintf(
		"Environment exception expired: rule '%s' for resource '%s' expired on %s (approved by %s)",
		[ex.rule, ex.resource, ex.expires, ex.approved_by],
	)
}
