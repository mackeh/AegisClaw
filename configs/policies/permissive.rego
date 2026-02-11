package aegisclaw.policy

import rego.v1

# Permissive policy: allow most operations, log everything.
# Only critical-risk actions require approval.
default decision = "allow"

# Require approval for critical-risk scopes.
decision = "require_approval" if {
	input.scope.risk == "critical"
}

# Require approval for unsigned skills with high-risk scopes.
decision = "require_approval" if {
	input.scope.risk == "high"
	not input.skill_signed
}
