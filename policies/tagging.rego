# POLICY: Required Resource Tagging
# SEVERITY: deny (missing required tags), warn (missing recommended tags)
#
# Enforces a consistent tagging standard across all taggable AWS resources.
# Required tags (deny):  Environment, Project
# Recommended tags (warn): ManagedBy

package main

import rego.v1

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

# Tags that MUST be present — missing any of these blocks the merge
required_tags := {"Environment", "Project"}

# Tags that SHOULD be present — flagged but don't block
recommended_tags := {"ManagedBy"}

# Resource types that support tags and should be checked.
# This list covers the most common AWS resources; expand as needed.
taggable_resource_types := {
	"aws_s3_bucket",
	"aws_instance",
	"aws_security_group",
	"aws_ebs_volume",
	"aws_db_instance",
	"aws_vpc",
	"aws_subnet",
}

# ──────────────────────────────────────────────
# DENY: Missing required tags
# ──────────────────────────────────────────────

deny contains msg if {
	resource := input.resource_changes[_]
	taggable_resource_types[resource.type]
	is_create_or_update(resource)

	some tag_key in required_tags
	not has_tag(resource, tag_key)

	msg := sprintf(
		"DENY: %v '%v' is missing required tag '%v'. Remediation: Add `%v = \"...\"` to the resource's tags block.",
		[resource.type, resource.address, tag_key, tag_key],
	)
}

# Also deny when the tags block itself is null/missing
deny contains msg if {
	resource := input.resource_changes[_]
	taggable_resource_types[resource.type]
	is_create_or_update(resource)

	# tags is null (no tags block at all)
	resource.change.after.tags == null

	msg := sprintf(
		"DENY: %v '%v' has no tags. Remediation: Add a tags block with at least: %v.",
		[resource.type, resource.address, concat(", ", required_tags)],
	)
}

# ──────────────────────────────────────────────
# WARN: Missing recommended tags
# ──────────────────────────────────────────────

warn contains msg if {
	resource := input.resource_changes[_]
	taggable_resource_types[resource.type]
	is_create_or_update(resource)

	# Only warn if the resource HAS tags (not null) — if tags are null,
	# the deny rule above already fires, no need to pile on warnings.
	resource.change.after.tags != null

	some tag_key in recommended_tags
	not has_tag(resource, tag_key)

	msg := sprintf(
		"WARN: %v '%v' is missing recommended tag '%v'. Best practice: Add it for resource tracking.",
		[resource.type, resource.address, tag_key],
	)
}
