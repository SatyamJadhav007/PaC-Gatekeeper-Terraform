# POLICY: S3 Bucket Security
# SEVERITY: deny (public exposure), warn (best-practice hardening)
#
# Covers the modern AWS provider v4+ resource model where bucket settings
# are split across aws_s3_bucket, aws_s3_bucket_public_access_block,
# aws_s3_bucket_versioning, and aws_s3_bucket_server_side_encryption_configuration.

package main

import rego.v1

# ──────────────────────────────────────────────
# DENY: Public ACL on S3 bucket
# ──────────────────────────────────────────────
# The `acl` attribute is deprecated in provider v4+ but still accepted.
# If someone sets it to public-read or public-read-write, that's an
# immediate, high-severity exposure.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket"
	is_create_or_update(resource)

	dangerous_acls := {"public-read", "public-read-write"}
	dangerous_acls[resource.change.after.acl]

	msg := sprintf(
		"DENY: S3 bucket '%v' has a public ACL ('%v'). Remediation: Remove the `acl` attribute or set it to 'private'.",
		[resource.address, resource.change.after.acl],
	)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_acl"
	is_create_or_update(resource)

	dangerous_acls := {"public-read", "public-read-write"}
	dangerous_acls[resource.change.after.acl]

	msg := sprintf(
		"DENY: S3 bucket ACL '%v' is public ('%v'). Remediation: Set the `acl` attribute to 'private' or remove it.",
		[resource.address, resource.change.after.acl],
	)
}

# ──────────────────────────────────────────────
# DENY: Public access block with any flag disabled
# ──────────────────────────────────────────────
# All four flags must be true. Any single false flag is a violation —
# each flag controls a different attack surface.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_public_access_block"
	is_create_or_update(resource)

	flags := {
		"block_public_acls": resource.change.after.block_public_acls,
		"block_public_policy": resource.change.after.block_public_policy,
		"ignore_public_acls": resource.change.after.ignore_public_acls,
		"restrict_public_buckets": resource.change.after.restrict_public_buckets,
	}

	some flag_name, flag_value in flags
	flag_value == false

	msg := sprintf(
		"DENY: Public access block '%v' has '%v' set to false. Remediation: Set all four public access block flags to true.",
		[resource.address, flag_name],
	)
}

# ──────────────────────────────────────────────
# WARN: S3 bucket versioning not enabled
# ──────────────────────────────────────────────
# Versioning protects against accidental deletes and overwrites.
# Not a hard block, but worth flagging in the PR.

warn contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_versioning"
	is_create_or_update(resource)

	# versioning_configuration is an array of objects in the plan JSON
	config := resource.change.after.versioning_configuration[_]
	config.status != "Enabled"

	msg := sprintf(
		"WARN: S3 bucket versioning '%v' has status '%v'. Best practice: Enable versioning to protect against accidental data loss.",
		[resource.address, config.status],
	)
}
