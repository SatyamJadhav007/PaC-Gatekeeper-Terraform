# Tests for policies/ec2_sizing.rego
# Covers allowed types, denied types, and edge cases.

package main

import rego.v1

# ════════════════════════════════════════════════
# DENY: Oversized / non-allowed instance types
# ════════════════════════════════════════════════

test_deny_oversized_instance if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.big",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "m5.24xlarge",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_deny_gpu_instance if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.gpu",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "p3.2xlarge",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_deny_metal_instance if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.metal",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "m5.metal",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# ALLOW: Approved instance types
# ════════════════════════════════════════════════

test_allow_t3_micro if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.small",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "t3.micro",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_allow_t2_micro if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.free_tier",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "t2.micro",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_allow_m5_large if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.prod",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "m5.large",
					"tags": {"Environment": "prod", "Project": "test"},
				},
			},
		}],
	}
}

test_allow_t3a_medium if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.amd",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "t3a.medium",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# Edge cases
# ════════════════════════════════════════════════

# Updating an existing instance to an oversized type should also deny
test_deny_update_to_oversized if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.resized",
			"type": "aws_instance",
			"change": {
				"actions": ["update"],
				"before": {"instance_type": "t3.micro"},
				"after": {
					"instance_type": "r5.4xlarge",
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_ignore_instance_being_deleted if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.deleted",
			"type": "aws_instance",
			"change": {
				"actions": ["delete"],
				"before": {"instance_type": "m5.24xlarge"},
				"after": null,
			},
		}],
	}
}

# Non-EC2 resources should not be affected
test_ignore_non_ec2_resource if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_lambda_function.big",
			"type": "aws_lambda_function",
			"change": {
				"actions": ["create"],
				"after": {
					"function_name": "big-lambda",
					"memory_size": 10240,
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}
