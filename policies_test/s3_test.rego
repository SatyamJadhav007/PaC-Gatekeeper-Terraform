# Tests for policies/s3.rego
# Tests both compliant (should pass) and violating (should trigger deny/warn) inputs.

package main

import rego.v1

# ════════════════════════════════════════════════
# DENY: Public ACL
# ════════════════════════════════════════════════

test_deny_s3_public_read_acl if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.bad",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "bad-bucket",
					"acl": "public-read",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_deny_s3_public_read_write_acl if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.bad",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "bad-bucket",
					"acl": "public-read-write",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_allow_s3_private_acl if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.good",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "good-bucket",
					"acl": "private",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_deny_s3_bucket_acl_public_read if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket_acl.bad",
			"type": "aws_s3_bucket_acl",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "bad-bucket",
					"acl": "public-read",
				},
			},
		}],
	}
}

test_allow_s3_bucket_acl_private if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket_acl.good",
			"type": "aws_s3_bucket_acl",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "good-bucket",
					"acl": "private",
				},
			},
		}],
	}
}

test_allow_s3_no_acl_attribute if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.good",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "good-bucket",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# DENY: Public access block disabled
# ════════════════════════════════════════════════

test_deny_s3_public_access_block_disabled if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket_public_access_block.bad",
			"type": "aws_s3_bucket_public_access_block",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "my-bucket",
					"block_public_acls": false,
					"block_public_policy": true,
					"ignore_public_acls": true,
					"restrict_public_buckets": true,
				},
			},
		}],
	}
}

test_deny_s3_public_access_block_all_disabled if {
	result := deny with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket_public_access_block.bad",
			"type": "aws_s3_bucket_public_access_block",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "my-bucket",
					"block_public_acls": false,
					"block_public_policy": false,
					"ignore_public_acls": false,
					"restrict_public_buckets": false,
				},
			},
		}],
	}

	# Should produce 4 violations — one per disabled flag
	count(result) == 4
}

test_allow_s3_public_access_block_all_enabled if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket_public_access_block.good",
			"type": "aws_s3_bucket_public_access_block",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "my-bucket",
					"block_public_acls": true,
					"block_public_policy": true,
					"ignore_public_acls": true,
					"restrict_public_buckets": true,
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# WARN: Versioning not enabled
# ════════════════════════════════════════════════

test_warn_s3_versioning_suspended if {
	count(warn) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket_versioning.no_ver",
			"type": "aws_s3_bucket_versioning",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "my-bucket",
					"versioning_configuration": [{"status": "Suspended", "mfa_delete": "Disabled"}],
				},
			},
		}],
	}
}

test_no_warn_s3_versioning_enabled if {
	count(warn) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket_versioning.good",
			"type": "aws_s3_bucket_versioning",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "my-bucket",
					"versioning_configuration": [{"status": "Enabled", "mfa_delete": "Disabled"}],
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# Edge cases
# ════════════════════════════════════════════════

test_ignore_s3_bucket_being_deleted if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.deleted",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["delete"],
				"before": {"bucket": "old-bucket", "acl": "public-read"},
				"after": null,
			},
		}],
	}
}
