# Product Requirements Document

**Product**: RepoLens
**Version**: 0.1.0
**Status**: Alpha

---

## Product Vision

RepoLens provides developers, CI pipelines, and security reviewers with a fast, safe, and reproducible view of a repository's health. It answers the question "what is wrong with this repository, structurally and dependency-wise, before I run or install it?" The tool operates entirely statically: it reads files, it never executes them, and it never installs anything from the target repository.

The guiding principle is that a health checker must be trustworthy enough to run against repositories you do not control. That trust comes from strict isolation, transparent rule definitions, and deterministic, fingerprintable output.

---

## Target Users

**Developers maintaining open-source or internal projects**: They run RepoLens locally or in CI to catch missing documentation, misconfigured tooling, insecure dependency configurations, and code quality issues before they accumulate.

**CI pipelines**: RepoLens runs as a step in a GitHub Actions or other CI workflow. It exits with a non-zero code when findings are present, allowing the pipeline to gate merges on repository health. It requires no service account, no Docker daemon, and no network access in its default configuration.

**Security reviewers evaluating third-party dependencies**: Before adopting a dependency, a security reviewer can run RepoLens against it to check for missing lockfiles, known-vulnerable dependencies (with `--network-checks`), secrets accidentally committed, and absent LICENSE or README files.

---

## Core Requirements

### What RepoLens must do

- Accept a filesystem path to a repository root and produce a structured report of findings.
- Discover all relevant files within configurable resource limits (file count, file size, total bytes, directory depth).
- Respect `.gitignore` rules when deciding which files to include.
- Run the following categories of checks: repository structure and hygiene, Python static analysis (Ruff, Bandit), JavaScript/TypeScript static analysis (Biome), dependency manifest and lockfile parsing, documentation cross-reference validation, test infrastructure checks, and (opt-in) OSV.dev vulnerability advisory lookup.
- Produce findings with stable rule IDs, severity levels, human-readable explanations, and actionable recommendations.
- Assign a SHA-256 fingerprint to each finding, derived from stable fields, so that findings can be deduplicated and tracked across scans.
- Redact secrets and credentials from all evidence strings before they are stored in a report.
- Exit with documented exit codes (0, 1, 2, 3, 130) so that CI pipelines can act on the result.
- Run on Python 3.11, 3.12, and 3.13 on Linux, macOS, and Windows.
- Pass `mypy --strict` type checking.

### What RepoLens must not do

- Execute any code, script, or binary from the target repository.
- Install any package from the target repository.
- Follow symlinks during discovery.
- Make network requests without explicit user opt-in (`--network-checks`).
- Store or log file content that has not been passed through the redaction layer.
- Require root or administrator privileges.
- Require Docker or any container runtime.
- Require any credentials in its default (no-network) mode.

---

## Non-Functional Requirements

### Performance

- A scan of a typical medium-sized repository (1,000 files, 10 MiB total) must complete in under 30 seconds on a modern developer laptop, including subprocess calls to Ruff, Bandit, and Biome where installed.
- Discovery must complete in bounded time and memory regardless of the target repository's size, enforced by per-file and total byte caps.
- Subprocess calls are individually bounded by a 30-second timeout. A single slow tool call cannot stall the entire scan indefinitely.

### Security

- No code from the target repository is trusted or executed under any circumstances.
- Subprocess invocations use `shell=False` and an environment allowlist.
- Sensitive filenames are detected and excluded from content reads during discovery.
- All evidence strings are redacted before storage.
- OSV.dev queries transmit only package name, version, and ecosystem.

### Portability

- RepoLens runs without modification on Linux, macOS, and Windows.
- External tools (Ruff, Bandit, Biome) are optional: if not installed, their respective analyzers record an `unavailable` outcome and the scan continues.
- No C extensions are required by RepoLens itself.

### Determinism

- Given the same repository state and the same configuration, RepoLens must produce the same set of findings with the same fingerprints.
- Finding fingerprints must not change when non-semantic fields (such as scan timestamp or duration) change.

### Observability

- Each analyzer records its outcome status, duration in milliseconds, and whether coverage was truncated or incomplete.
- Discovery records the count of skipped files and the reasons for skipping.
- The report schema includes a version field so that consumers can detect schema changes.

---

## Out of Scope

The following items are explicitly out of scope for the current version and near-term roadmap:

- Automatic remediation or pull request creation.
- Runtime analysis or dynamic testing.
- Code coverage measurement (RepoLens checks for coverage configuration but does not run tests).
- Support for languages other than Python and JavaScript/TypeScript (Go, Rust, Java, etc. are not analysed).
- A graphical user interface (a web interface is planned for Stage 5 but is not in scope for v0.1.0).
- Integration with issue trackers or notification systems.
- Per-rule suppression comments in source files (`.repolens-ignore` or similar).
- Customisable rule sets or user-defined rules.

---

## Success Metrics

The following criteria indicate that v0.1.0 has met its goals:

- All tests pass on Ubuntu, macOS, and Windows across Python 3.11, 3.12, and 3.13 in CI.
- `mypy --strict` reports zero errors.
- Ruff and Ruff format checks pass on the RepoLens source itself.
- The tool correctly identifies the full set of expected findings when run against a set of reference repositories with known issues.
- A scan of a 10,000-file repository completes within the subprocess timeout budget without running out of memory.
- No secrets or credentials appear in any `Finding.evidence` field in the test suite output.
- The `ScanReport` schema can be round-tripped through JSON without loss.
