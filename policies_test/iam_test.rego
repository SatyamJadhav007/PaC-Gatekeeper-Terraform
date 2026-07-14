# Tests for policies/iam.rego
# Covers wildcard IAM policies (deny) for managed and inline policies.

package main

import rego.v1

# ════════════════════════════════════════════════
# DENY: Wildcard admin IAM managed policy
# ════════════════════════════════════════════════

test_deny_iam_wildcard_admin_policy if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_policy.admin",
			"type": "aws_iam_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "admin-policy",
					"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
				},
			},
		}],
	}
}

test_allow_iam_scoped_policy if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_policy.s3_read",
			"type": "aws_iam_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "s3-read-policy",
					"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:ListBucket\"],\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}",
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# DENY: Wildcard admin IAM inline role policy
# ════════════════════════════════════════════════

test_deny_iam_role_policy_wildcard if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_role_policy.admin",
			"type": "aws_iam_role_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "admin-inline",
					"role": "my-role",
					"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
				},
			},
		}],
	}
}

test_allow_iam_role_policy_scoped if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_role_policy.scoped",
			"type": "aws_iam_role_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "ec2-describe",
					"role": "my-role",
					"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"ec2:DescribeInstances\",\"Resource\":\"arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0\"}]}",
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# DENY: Wildcard admin IAM user policy
# ════════════════════════════════════════════════

test_deny_iam_user_policy_wildcard if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_user_policy.admin",
			"type": "aws_iam_user_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "user-admin",
					"user": "bad-user",
					"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# Edge cases
# ════════════════════════════════════════════════

# Wildcard Action but scoped Resource should NOT trigger
test_allow_wildcard_action_scoped_resource if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_policy.partial_wildcard",
			"type": "aws_iam_policy",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "s3-admin",
					"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}",
				},
			},
		}],
	}
}

test_ignore_iam_policy_being_deleted if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_policy.deleted",
			"type": "aws_iam_policy",
			"change": {
				"actions": ["delete"],
				"before": {
					"name": "old-admin-policy",
					"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
				},
				"after": null,
			},
		}],
	}
}
