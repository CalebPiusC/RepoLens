# RepoLens Documentation

This folder contains design and process documentation for RepoLens. The
[root README](../README.md) is the authoritative reference for installation, CLI options, exit
codes, and the versioned JSON output contract (schema `1.1.0`); the documents here explain how
the system is built and how to work on it, and link back to the README instead of redefining
behavior.

## Contents

| Document | Description |
| --- | --- |
| [Architecture](./architecture/README.md) | Scan pipeline, module responsibilities, data flow, output formats, and security boundaries. |
| [Architecture Decision Records](./adr/README.md) | Index of ADRs recording significant design decisions (ADR-001 to ADR-006). |
| [Product Requirements](./prd/README.md) | Product vision, target users, scope, non-functional requirements, and success criteria. |
| [Contributing Guide](./contributing/README.md) | Development setup with `pip`, quality gates that match CI, how to write an analyzer, and the pull-request process. |
| [Security Model](./security/README.md) | Threat model, discovery and subprocess safety, secret redaction, OSV.dev data minimization, and how to report a vulnerability in RepoLens itself. |
| [Rules Reference](./rules/README.md) | Every rule ID RepoLens can emit, with category, severity, and trigger, plus fingerprint and threshold semantics. |
| [Changelog](./changelog/README.md) | Unreleased changes, in Keep a Changelog format. RepoLens has no tagged release yet. |

See also the [analyzers package notes](../src/repolens/analyzers/README.md) and the
[test suite guide](../tests/README.md).
