# POLICY: Security Group Network Rules
# SEVERITY: deny (dangerous port exposure), warn (overly broad CIDR)
#
# Checks both inline ingress rules on aws_security_group and standalone
# aws_security_group_rule resources of type "ingress".

package main

import rego.v1

# ──────────────────────────────────────────────
# DENY: SSH (port 22) open to the world
# ──────────────────────────────────────────────

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	is_create_or_update(resource)

	rule := resource.change.after.ingress[_]
	rule.from_port <= 22
	rule.to_port >= 22
	rule.cidr_blocks[_] == "0.0.0.0/0"

	msg := sprintf(
		"DENY: Security group '%v' allows SSH (port 22) from 0.0.0.0/0. Remediation: Restrict the source CIDR to your IP range or use a bastion host.",
		[resource.address],
	)
}

# IPv6 variant
deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	is_create_or_update(resource)

	rule := resource.change.after.ingress[_]
	rule.from_port <= 22
	rule.to_port >= 22
	rule.ipv6_cidr_blocks[_] == "::/0"

	msg := sprintf(
		"DENY: Security group '%v' allows SSH (port 22) from ::/0 (IPv6). Remediation: Restrict the source CIDR.",
		[resource.address],
	)
}

# ──────────────────────────────────────────────
# DENY: RDP (port 3389) open to the world
# ──────────────────────────────────────────────

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	is_create_or_update(resource)

	rule := resource.change.after.ingress[_]
	rule.from_port <= 3389
	rule.to_port >= 3389
	rule.cidr_blocks[_] == "0.0.0.0/0"

	msg := sprintf(
		"DENY: Security group '%v' allows RDP (port 3389) from 0.0.0.0/0. Remediation: Restrict the source CIDR or use a VPN.",
		[resource.address],
	)
}

# ──────────────────────────────────────────────
# DENY: All-ports / all-protocols open to the world
# ──────────────────────────────────────────────
# protocol "-1" means all protocols. from_port 0, to_port 65535 means
# the entire port range. Either pattern from 0.0.0.0/0 is a critical risk.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	is_create_or_update(resource)

	rule := resource.change.after.ingress[_]
	rule.protocol == "-1"
	rule.cidr_blocks[_] == "0.0.0.0/0"

	msg := sprintf(
		"DENY: Security group '%v' allows ALL traffic (protocol -1) from 0.0.0.0/0. Remediation: Restrict both the protocol and source CIDR.",
		[resource.address],
	)
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	is_create_or_update(resource)

	rule := resource.change.after.ingress[_]
	rule.from_port == 0
	rule.to_port == 65535
	rule.protocol == "tcp"
	rule.cidr_blocks[_] == "0.0.0.0/0"

	msg := sprintf(
		"DENY: Security group '%v' allows all TCP ports (0-65535) from 0.0.0.0/0. Remediation: Open only the specific ports you need.",
		[resource.address],
	)
}

# ──────────────────────────────────────────────
# DENY: Standalone security group rule — SSH/RDP from world
# ──────────────────────────────────────────────
# aws_security_group_rule is an alternative to inline ingress blocks.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group_rule"
	is_create_or_update(resource)

	resource.change.after.type == "ingress"
	dangerous_ports := {22, 3389}
	dangerous_ports[resource.change.after.from_port]
	resource.change.after.cidr_blocks[_] == "0.0.0.0/0"

	msg := sprintf(
		"DENY: Security group rule '%v' allows port %v from 0.0.0.0/0. Remediation: Restrict the source CIDR.",
		[resource.address, resource.change.after.from_port],
	)
}

# ──────────────────────────────────────────────
# WARN: Any other port open to 0.0.0.0/0
# ──────────────────────────────────────────────
# Not SSH/RDP/all-ports, but still open to the entire internet.
# Worth flagging so reviewers can confirm it's intentional (e.g., port 443).

warn contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	is_create_or_update(resource)

	rule := resource.change.after.ingress[_]
	rule.cidr_blocks[_] == "0.0.0.0/0"

	# Only warn if it's NOT one of the already-denied patterns
	rule.protocol != "-1"
	not _is_ssh_port(rule)
	not _is_rdp_port(rule)
	not _is_all_tcp_ports(rule)

	msg := sprintf(
		"WARN: Security group '%v' allows port %v-%v/%v from 0.0.0.0/0. Verify this broad exposure is intentional.",
		[resource.address, rule.from_port, rule.to_port, rule.protocol],
	)
}

# Private helpers to avoid warn firing on already-denied patterns
_is_ssh_port(rule) if {
	rule.from_port <= 22
	rule.to_port >= 22
}

_is_rdp_port(rule) if {
	rule.from_port <= 3389
	rule.to_port >= 3389
}

_is_all_tcp_ports(rule) if {
	rule.from_port == 0
	rule.to_port == 65535
	rule.protocol == "tcp"
}
