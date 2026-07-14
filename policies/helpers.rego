# POLICY: Shared Helpers
# PURPOSE: Reusable rules for filtering and accessing Terraform plan resources.
#          Used by all other policy files in this package.

package main

import rego.v1

# ──────────────────────────────────────────────
# Action Filters
# ──────────────────────────────────────────────

# True when a resource is being created
is_create(resource) if {
	resource.change.actions[_] == "create"
}

# True when a resource is being updated in-place
is_update(resource) if {
	resource.change.actions[_] == "update"
}

# True when a resource is being created or updated (the common case for policy checks)
is_create_or_update(resource) if {
	is_create(resource)
}

is_create_or_update(resource) if {
	is_update(resource)
}

# ──────────────────────────────────────────────
# Resource Lookups
# ──────────────────────────────────────────────

# Returns all resource_changes of a given type that are being created or updated.
# Usage: planned_resources("aws_s3_bucket") → array of matching resources
planned_resources(type) = resources if {
	resources := [r |
		r := input.resource_changes[_]
		r.type == type
		is_create_or_update(r)
	]
}

# Returns a single resource_change by its address (e.g., "aws_s3_bucket.my_bucket")
resource_by_address(addr) = resource if {
	resource := input.resource_changes[_]
	resource.address == addr
}

# ──────────────────────────────────────────────
# Tag Helpers
# ──────────────────────────────────────────────

# True when a resource has a specific tag key set to a non-empty value
has_tag(resource, key) if {
	resource.change.after.tags[key]
}

# Returns the tags object, or an empty object if tags is null/missing
get_tags(resource) = tags if {
	tags := resource.change.after.tags
} else = tags if {
	tags := {}
}
