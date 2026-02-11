package aegisclaw.policy

import rego.v1

# Strict policy: deny by default, everything requires explicit approval.
default decision = "deny"

# Only proceed if the user has explicitly approved the action.
decision = "allow" if {
	input.approval == true
}

# Allow approval flow for any scope — nothing auto-allows.
decision = "require_approval" if {
	not input.approval
}
