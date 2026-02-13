# Repository Guidelines

## Project Structure & Module Organization
`AegisClaw` is a Go-first monorepo.
- CLI entrypoint: `cmd/aegisclaw/`
- Core runtime packages: `internal/` (policy, sandbox, server, audit, secrets, eBPF, cluster, etc.)
- Config and policy templates: `configs/` (`policies/*.rego`, seccomp profiles)
- Sample/packaged skills: `skills/` and `examples/skills/`
- Fuzz-specific docs/tests: `tests/fuzz/`
- VS Code extension: `vscode-extension/` (TypeScript)
- Docs/media assets: `README.md`, `aegisclaw-roadmap.md`, `assets/`

## Build, Test, and Development Commands
- `go mod tidy`: sync and clean module dependencies.
- `go generate ./...`: regenerate generated artifacts (including eBPF bindings).
- `go build -o aegisclaw ./cmd/aegisclaw`: build the CLI locally.
- `go test -v ./...`: run unit/integration tests across all packages.
- `go test -fuzz=FuzzPolicy -fuzztime=30s ./internal/policy`: run policy fuzzing.
- `go test -fuzz=FuzzSandboxConfig -fuzztime=30s ./internal/sandbox`: run sandbox fuzzing.
- `cd vscode-extension && npm install && npm run compile`: build extension artifacts.

## Coding Style & Naming Conventions
- Follow standard Go formatting: run `gofmt` on changed Go files before PR.
- Prefer small, focused packages under `internal/<domain>`.
- Go packages/files: lowercase, descriptive (`internal/guardrails/guardrails.go`).
- Exported identifiers: `PascalCase`; internal helpers: `camelCase`.
- Tests: `*_test.go`, with `TestXxx` and `FuzzXxx` function names.
- Linting expectation: `golangci-lint` (per `CONTRIBUTING.md`).

## Testing Guidelines
- Add/update tests with every behavior change, bug fix, or security control update.
- Keep tests adjacent to implementation in `internal/*`.
- For security-sensitive paths (policy, sandbox, audit), include negative-path assertions and malformed input cases.
- No explicit coverage threshold is defined; maintain or improve effective coverage in touched modules.

## Commit & Pull Request Guidelines
- Use Conventional Commit-style prefixes seen in history: `feat:`, `fix:`, `test:`, `docs:`, `chore:`.
- Keep commits scoped to one logical change and include tests when applicable.
- PRs should include a clear summary/motivation, linked issue (if available), verification commands run (for example `go test -v ./...`), and screenshots for UI changes (`internal/server/ui`, `vscode-extension`).

## Security & Configuration Tips
- Never commit credentials or `.env` secrets; use `./aegisclaw secrets ...` commands.
- Follow least-privilege scopes in skill manifests and policy files.
- Report vulnerabilities privately via `security@aegisclaw.dev` (see `SECURITY.md`).
