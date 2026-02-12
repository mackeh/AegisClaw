# AegisClaw Security Fuzzing Suite

This directory contains fuzzing tests to identify vulnerabilities and edge cases in critical AegisClaw components, particularly the sandbox boundary and policy engine.

## Targets

1.  **Policy Engine**: Fuzzing the OPA/Rego policy evaluation with malformed or edge-case `ScopeRequests`.
2.  **Sandbox Config**: Fuzzing the `sandbox.Config` and Docker executor inputs to ensure robust handling of invalid image names, commands, and mount configurations.
3.  **Audit Log**: Fuzzing the audit log parser and verification logic to ensure it can handle corrupted or malicious log files without crashing or returning false positives.

## Running Fuzz Tests

AegisClaw uses Go's native fuzzing support (introduced in Go 1.18).

```bash
# Run policy engine fuzz tests
go test -fuzz=FuzzPolicy -fuzztime=30s ./internal/policy

# Run sandbox config fuzz tests
go test -fuzz=FuzzSandboxConfig -fuzztime=30s ./internal/sandbox
```
