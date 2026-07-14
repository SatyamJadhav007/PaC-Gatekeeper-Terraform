# Tests for policies/encryption.rego
# Covers EBS volumes (deny), RDS instances (deny), and EC2 root block device (warn).

package main

import rego.v1

# ════════════════════════════════════════════════
# DENY: Unencrypted EBS volume
# ════════════════════════════════════════════════

test_deny_unencrypted_ebs if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_ebs_volume.unenc",
			"type": "aws_ebs_volume",
			"change": {
				"actions": ["create"],
				"after": {
					"availability_zone": "us-east-1a",
					"size": 20,
					"encrypted": false,
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_allow_encrypted_ebs if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_ebs_volume.enc",
			"type": "aws_ebs_volume",
			"change": {
				"actions": ["create"],
				"after": {
					"availability_zone": "us-east-1a",
					"size": 20,
					"encrypted": true,
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# DENY: Unencrypted RDS instance
# ════════════════════════════════════════════════

test_deny_unencrypted_rds if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_db_instance.unenc",
			"type": "aws_db_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"engine": "mysql",
					"instance_class": "db.t3.micro",
					"storage_encrypted": false,
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_allow_encrypted_rds if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_db_instance.enc",
			"type": "aws_db_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"engine": "postgres",
					"instance_class": "db.t3.micro",
					"storage_encrypted": true,
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# WARN: Unencrypted EC2 root block device
# ════════════════════════════════════════════════

test_warn_unencrypted_root_block if {
	count(warn) > 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.unenc_root",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "t3.micro",
					"root_block_device": [{"encrypted": false, "volume_size": 8}],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_no_warn_encrypted_root_block if {
	count(warn) == 0 with input as {
		"resource_changes": [{
			"address": "aws_instance.enc_root",
			"type": "aws_instance",
			"change": {
				"actions": ["create"],
				"after": {
					"instance_type": "t3.micro",
					"root_block_device": [{"encrypted": true, "volume_size": 8}],
					"tags": {"Environment": "dev", "Project": "test", "ManagedBy": "terraform"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# Edge cases
# ════════════════════════════════════════════════

test_ignore_ebs_being_deleted if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_ebs_volume.deleted",
			"type": "aws_ebs_volume",
			"change": {
				"actions": ["delete"],
				"before": {"encrypted": false, "size": 20},
				"after": null,
			},
		}],
	}
}

# Update to unencrypted should still deny
test_deny_update_ebs_to_unencrypted if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_ebs_volume.changed",
			"type": "aws_ebs_volume",
			"change": {
				"actions": ["update"],
				"before": {"encrypted": true, "size": 20},
				"after": {
					"size": 50,
					"encrypted": false,
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}
