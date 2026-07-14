# POLICY: IAM Policy Guardrails
# SEVERITY: deny
#
# Prevents creation of overly permissive IAM policies with wildcard
# Action/Resource combinations ("admin" policies). This is one of the
# most common findings in AWS security audits.

package main

import rego.v1

# ──────────────────────────────────────────────
# DENY: Wildcard admin IAM policy (Action: *, Resource: *)
# ──────────────────────────────────────────────
# Catches both aws_iam_policy (standalone managed policy) and
# aws_iam_user_policy (inline user policy).

deny contains msg if {
	resource := input.resource_changes[_]
	_is_iam_policy_resource(resource.type)
	is_create_or_update(resource)

	# The policy document is a JSON-encoded string in the plan
	policy_doc := resource.change.after.policy

	# Check if the policy string contains the wildcard pattern
	contains(policy_doc, "\"Action\"")
	contains(policy_doc, "\"*\"")
	contains(policy_doc, "\"Resource\"")
	_has_wildcard_action_and_resource(policy_doc)

	msg := sprintf(
		"DENY: IAM policy '%v' grants wildcard permissions (Action: *, Resource: *). Remediation: Follow least-privilege — specify only the actions and resources needed.",
		[resource.address],
	)
}

# ──────────────────────────────────────────────
# DENY: Wildcard admin IAM role policy (inline)
# ──────────────────────────────────────────────

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "aws_iam_role_policy"
	is_create_or_update(resource)

	policy_doc := resource.change.after.policy
	_has_wildcard_action_and_resource(policy_doc)

	msg := sprintf(
		"DENY: Inline IAM role policy '%v' grants wildcard permissions (Action: *, Resource: *). Remediation: Follow least-privilege principles.",
		[resource.address],
	)
}

# ──────────────────────────────────────────────
# Private helpers
# ──────────────────────────────────────────────

_is_iam_policy_resource(type) if {
	type == "aws_iam_policy"
}

_is_iam_policy_resource(type) if {
	type == "aws_iam_user_policy"
}

# Checks if a JSON policy string contains both a wildcard Action and wildcard Resource.
_has_wildcard_action_and_resource(policy_doc) if {
	contains(policy_doc, "\"*\"")
	_section_has_wildcard(policy_doc, "Action")
	_section_has_wildcard(policy_doc, "Resource")
}

# Heuristic: the section name appears before a wildcard in the string.
_section_has_wildcard(doc, section) if {
	pattern := concat("", ["\"", section, "\""])
	contains(doc, pattern)
}
