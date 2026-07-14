# Tests for policies/tagging.rego
# Covers required tags (deny), recommended tags (warn), null tags, and multiple resource types.

package main

import rego.v1

# ════════════════════════════════════════════════
# DENY: Missing required tags
# ════════════════════════════════════════════════

test_deny_missing_environment_tag if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.no_env",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "my-bucket",
					"tags": {"Project": "vidrn"},
				},
			},
		}],
	}
}

test_deny_missing_project_tag if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.no_project",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "t3.micro",
					"tags": {"Environment": "dev"},
				},
			},
		}],
	}
}

test_deny_missing_both_required_tags if {
	result := deny with input as {
		"resource_changes": [{
			"address": "aws_ebs_volume.no_tags",
			"type": "aws_ebs_volume",
			"change": {
				"actions": ["create"],
				"after": {
					"size": 20,
					"encrypted": true,
					"tags": {"Name": "data-vol"},
				},
			},
		}],
	}

	# Should produce 2 violations — one for Environment, one for Project
	count(result) == 2
}

test_deny_null_tags if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.null_tags",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "no-tags-bucket",
					"tags": null,
				},
			},
		}],
	}
}

test_allow_all_required_tags if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.good",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "good-bucket",
					"tags": {
						"Environment": "production",
						"Project": "vidrn",
					},
				},
			},
		}],
	}
}

# Test across a different taggable resource type
test_deny_ec2_missing_tags if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.untagged",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "t3.micro",
					"tags": {"Name": "web-server"},
				},
			},
		}],
	}
}

test_deny_db_instance_missing_tags if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_db_instance.untagged",
			"type": "aws_db_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"engine": "mysql",
					"instance_class": "db.t3.micro",
					"storage_encrypted": true,
					"tags": null,
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# Non-taggable resources should be ignored
# ════════════════════════════════════════════════

test_ignore_non_taggable_resource if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_route_table_association.main",
			"type": "aws_route_table_association",
			"change": {
				"actions": ["create"],
				"after": {
					"subnet_id": "subnet-123",
					"route_table_id": "rtb-456",
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# WARN: Missing recommended tags
# ════════════════════════════════════════════════

test_warn_missing_managed_by_tag if {
	count(warn) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.no_managed_by",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "my-bucket",
					"tags": {
						"Environment": "dev",
						"Project": "vidrn",
					},
				},
			},
		}],
	}
}

test_no_warn_when_all_tags_present if {
	count(warn) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.fully_tagged",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "my-bucket",
					"tags": {
						"Environment": "dev",
						"Project": "vidrn",
						"ManagedBy": "terraform",
					},
				},
			},
		}],
	}
}

# Warn should NOT fire when tags are null (deny already handles that)
test_no_warn_when_tags_null if {
	count(warn) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.null_tags",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {
					"bucket": "null-tags-bucket",
					"tags": null,
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# Edge cases
# ════════════════════════════════════════════════

test_ignore_tagged_resource_being_deleted if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.deleted",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["delete"],
				"before": {"bucket": "old", "tags": null},
				"after": null,
			},
		}],
	}
}
