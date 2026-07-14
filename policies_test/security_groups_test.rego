# Tests for policies/security_groups.rego
# Covers SSH, RDP, all-ports deny rules, standalone SG rules, and broad-CIDR warn.

package main

import rego.v1

# ════════════════════════════════════════════════
# DENY: SSH (port 22) open to world
# ════════════════════════════════════════════════

test_deny_ssh_open_to_world if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.bad_ssh",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-ssh-world",
					"ingress": [{
						"from_port": 22,
						"to_port": 22,
						"protocol": "tcp",
						"cidr_blocks": ["0.0.0.0/0"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_deny_ssh_open_to_world_ipv6 if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.bad_ssh_v6",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-ssh-world-v6",
					"ingress": [{
						"from_port": 22,
						"to_port": 22,
						"protocol": "tcp",
						"cidr_blocks": [],
						"ipv6_cidr_blocks": ["::/0"],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_allow_ssh_restricted_cidr if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.good_ssh",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-ssh-office",
					"ingress": [{
						"from_port": 22,
						"to_port": 22,
						"protocol": "tcp",
						"cidr_blocks": ["10.0.0.0/8"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# DENY: RDP (port 3389) open to world
# ════════════════════════════════════════════════

test_deny_rdp_open_to_world if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.bad_rdp",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-rdp-world",
					"ingress": [{
						"from_port": 3389,
						"to_port": 3389,
						"protocol": "tcp",
						"cidr_blocks": ["0.0.0.0/0"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_allow_rdp_restricted_cidr if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.good_rdp",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-rdp-vpn",
					"ingress": [{
						"from_port": 3389,
						"to_port": 3389,
						"protocol": "tcp",
						"cidr_blocks": ["172.16.0.0/12"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# DENY: All-ports / all-protocols open to world
# ════════════════════════════════════════════════

test_deny_all_protocols_open_to_world if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.bad_all",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-all-world",
					"ingress": [{
						"from_port": 0,
						"to_port": 0,
						"protocol": "-1",
						"cidr_blocks": ["0.0.0.0/0"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_deny_all_tcp_ports_open_to_world if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.bad_tcp_all",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-all-tcp-world",
					"ingress": [{
						"from_port": 0,
						"to_port": 65535,
						"protocol": "tcp",
						"cidr_blocks": ["0.0.0.0/0"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_allow_specific_port_open if {
	# Port 443 from 0.0.0.0/0 should NOT trigger deny (only warn)
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.web",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-https",
					"ingress": [{
						"from_port": 443,
						"to_port": 443,
						"protocol": "tcp",
						"cidr_blocks": ["0.0.0.0/0"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# DENY: Standalone security group rule
# ════════════════════════════════════════════════

test_deny_standalone_sg_rule_ssh_open if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group_rule.bad_ssh",
			"type": "aws_security_group_rule",
			"change": {
				"actions": ["create"],
				"after": {
					"type": "ingress",
					"from_port": 22,
					"to_port": 22,
					"protocol": "tcp",
					"cidr_blocks": ["0.0.0.0/0"],
					"security_group_id": "sg-123",
				},
			},
		}],
	}
}

test_allow_standalone_sg_rule_egress if {
	# Egress rules should not trigger the ingress deny
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group_rule.egress",
			"type": "aws_security_group_rule",
			"change": {
				"actions": ["create"],
				"after": {
					"type": "egress",
					"from_port": 0,
					"to_port": 0,
					"protocol": "-1",
					"cidr_blocks": ["0.0.0.0/0"],
					"security_group_id": "sg-123",
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# WARN: Broad CIDR on non-SSH/RDP port
# ════════════════════════════════════════════════

test_warn_broad_cidr_non_ssh_port if {
	count(warn) > 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.web",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-https",
					"ingress": [{
						"from_port": 443,
						"to_port": 443,
						"protocol": "tcp",
						"cidr_blocks": ["0.0.0.0/0"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
			},
		}],
	}
}

test_no_warn_restricted_cidr if {
	count(warn) == 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.internal",
			"type": "aws_security_group",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "allow-internal",
					"ingress": [{
						"from_port": 8080,
						"to_port": 8080,
						"protocol": "tcp",
						"cidr_blocks": ["10.0.0.0/8"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test", "ManagedBy": "terraform"},
				},
			},
		}],
	}
}

# ════════════════════════════════════════════════
# Edge case: deletion should not trigger
# ════════════════════════════════════════════════

test_ignore_sg_being_deleted if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_security_group.deleted",
			"type": "aws_security_group",
			"change": {
				"actions": ["delete"],
				"before": {
					"name": "old-sg",
					"ingress": [{
						"from_port": 22,
						"to_port": 22,
						"protocol": "tcp",
						"cidr_blocks": ["0.0.0.0/0"],
						"ipv6_cidr_blocks": [],
						"security_groups": [],
						"self": false,
					}],
					"egress": [],
					"tags": {"Environment": "dev", "Project": "test"},
				},
				"after": null,
			},
		}],
	}
}
