# Contributing to AegisClaw

First off, thanks for taking the time to contribute! 🎉

## How to Contribute

### Reporting Bugs

- Ensure the bug was not already reported by searching on GitHub under [Issues](https://github.com/mackeh/AegisClaw/issues).
- If you're unable to find an open issue addressing the problem, open a new one. Be sure to include a **title and clear description**, as well as as much relevant information as possible, including a code sample or an executable test case demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements

- Open a new issue with a clear title and detailed description.
- Explain **why** you want this enhancement and how it benefits the project.

### Pull Requests

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes (`go test ./...`).
4. Make sure your code lints (we use `golangci-lint`).
5. Issue that pull request!

## Development Setup

1. **Prerequisites**: Go 1.22+, Docker (for sandbox testing).
2. **Setup**:
   ```bash
   git clone https://github.com/your-fork/AegisClaw.git
   cd AegisClaw
   go mod download
   ```
3. **Build**:
   ```bash
   go build -o aegisclaw ./cmd/aegisclaw
   ```

## License

By contributing, you agree that your contributions will be licensed under its Apache-2.0 License.
