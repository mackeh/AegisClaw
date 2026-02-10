package aegisclaw.policy

import rego.v1

default decision = "require_approval"

# Allow reading files in /tmp or /home/user/safe
decision = "allow" if {
	input.scope.name == "files.read"
	is_safe_path(input.scope.resource)
}

# Always require approval for shell execution (redundant due to default, but explicit)
decision = "require_approval" if {
	input.scope.name == "shell.exec"
}

# Allow specific low risk actions (example)
decision = "allow" if {
	input.scope.name == "time.read"
}

is_safe_path(path) if {
	startswith(path, "/tmp")
}

is_safe_path(path) if {
	startswith(path, "/home/user/safe")
}
