# POLICY: EC2 Instance Sizing
# SEVERITY: deny
#
# Guards against accidental deployment of oversized or costly instance types.
# Only allow-listed types are permitted. This catches someone accidentally
# deploying an m5.24xlarge, a GPU instance, or a metal instance.

package main

import rego.v1

# ──────────────────────────────────────────────
# Allow-list
# ──────────────────────────────────────────────
# Covers free-tier (t2.micro), burstable (t3/t3a family),
# and one general-purpose size (m5.large) for production workloads.
# Adjust this list to match your actual usage in Vidrn's Terraform.

allowed_instance_types := {
	# Free-tier eligible
	"t2.micro",
	"t2.small",
	"t2.medium",
	# Burstable — current gen
	"t3.micro",
	"t3.small",
	"t3.medium",
	"t3.large",
	# Burstable — AMD variant (cheaper)
	"t3a.micro",
	"t3a.small",
	"t3a.medium",
	"t3a.large",
	# General-purpose — production ceiling
	"m5.large",
}

# ──────────────────────────────────────────────
# DENY: Instance type not in allow-list
# ──────────────────────────────────────────────

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_instance"
	is_create_or_update(resource)

	instance_type := resource.change.after.instance_type
	not allowed_instance_types[instance_type]

	msg := sprintf(
		"DENY: EC2 instance '%v' uses type '%v' which is not in the approved list. Remediation: Use one of: %v.",
		[resource.address, instance_type, concat(", ", allowed_instance_types)],
	)
}
