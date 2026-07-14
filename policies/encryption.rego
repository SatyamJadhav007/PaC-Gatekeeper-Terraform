# POLICY: Encryption at Rest
# SEVERITY: deny (EBS volumes, RDS instances), warn (EC2 root block device)
#
# Ensures all persistent storage is encrypted. Unencrypted storage is a
# compliance risk and often a finding in security audits.

package main

import rego.v1

# ──────────────────────────────────────────────
# DENY: Unencrypted EBS volume
# ──────────────────────────────────────────────

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_ebs_volume"
	is_create_or_update(resource)

	resource.change.after.encrypted == false

	msg := sprintf(
		"DENY: EBS volume '%v' does not have encryption enabled. Remediation: Set `encrypted = true` in the resource configuration.",
		[resource.address],
	)
}

# ──────────────────────────────────────────────
# DENY: Unencrypted RDS instance
# ──────────────────────────────────────────────

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_db_instance"
	is_create_or_update(resource)

	resource.change.after.storage_encrypted == false

	msg := sprintf(
		"DENY: RDS instance '%v' does not have storage encryption enabled. Remediation: Set `storage_encrypted = true` in the resource configuration.",
		[resource.address],
	)
}

# ──────────────────────────────────────────────
# WARN: Unencrypted EC2 root block device
# ──────────────────────────────────────────────
# AWS may default-encrypt depending on account settings, but if the plan
# explicitly shows encrypted=false on the root device, it's worth flagging.

warn contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_instance"
	is_create_or_update(resource)

	root_device := resource.change.after.root_block_device[_]
	root_device.encrypted == false

	msg := sprintf(
		"WARN: EC2 instance '%v' has an unencrypted root block device. Best practice: Set `encrypted = true` in the root_block_device block or enable default EBS encryption at the account level.",
		[resource.address],
	)
}
