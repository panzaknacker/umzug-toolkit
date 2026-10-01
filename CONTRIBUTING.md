# Contributing

Start with [Testing guide](docs/TESTING.md) and [PROJECT_STATUS.md](PROJECT_STATUS.md).
Keep changes focused and explain the problem, resulting behavior and affected
trust boundaries.

## Local validation

Prepare Linux, Python 3.11+, OpenSSL, Git and pytest in an isolated environment.

```sh
./scripts/static-checks.sh
python scripts/portfolio-demo.py
python scripts/transport-smoke.py
```

The full gate includes syntax checks, tests and a reproducible double offline
wheel build. Report whether optional ShellCheck and YARA checks ran. Keep the
[SELinux limitation](docs/KNOWN-ISSUES.md) visible alongside results.

Run the relevant checks before submitting a change and record their actual
results, environment and skipped checks. Format Go changes with `gofmt`.
Behavior changes need regression coverage for rejected inputs and failure
paths as well as the intended workflow.

## Review expectations

Preserve explicit approvals, pinned trust, failure handling and recovery
boundaries. Update the component status when a capability or its qualification
changes. Distinguish local, simulated and deployed results.

Use synthetic fixtures. Do not commit generated binaries, private state,
credentials, real inventories or copied third-party code without its notices.
Report sensitive findings through [SECURITY.md](SECURITY.md).

## Source terms

Contributions follow the existing [GPL-3.0-or-later license](LICENSE).
