package aegisclaw.policy

import rego.v1

# Standard policy: allow known-safe operations, approve high-risk ones.
default decision = "require_approval"

# Allow low-risk file reads in safe directories.
decision = "allow" if {
	input.scope.name == "files.read"
	is_safe_path(input.scope.resource)
}

# Allow signed skills with low-risk scopes.
decision = "allow" if {
	input.scope.risk == "low"
	input.skill_signed == true
}

# Always require approval for shell execution.
decision = "require_approval" if {
	input.scope.name == "shell.exec"
}

# Always require approval for secret access.
decision = "require_approval" if {
	input.scope.name == "secrets.access"
}

# Deny unsigned skills requesting critical scopes.
decision = "deny" if {
	input.scope.risk == "critical"
	not input.skill_signed
}

is_safe_path(path) if {
	startswith(path, "/tmp")
}

is_safe_path(path) if {
	startswith(path, "/home/user/safe")
}
