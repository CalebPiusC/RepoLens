# RepoLens Documentation

This folder contains the full technical and product documentation for RepoLens. Each subdirectory covers a distinct aspect of the project: from high-level product goals and architectural decisions through to contributor guides, security policies, and the complete rules reference. Start with the architecture document if you want to understand how the system works, or jump directly to the contributing guide if you are setting up a development environment.

## Contents

| Document | Description |
|---|---|
| [Architecture](./architecture/README.md) | Full description of the scan pipeline, module responsibilities, data flow, and security boundaries. |
| [ADR Index](./adr/README.md) | Index of all Architecture Decision Records explaining the key design choices made during development. |
| [Product Requirements](./prd/README.md) | Product vision, target users, core and non-functional requirements, out-of-scope items, and success metrics. |
| [Contributing Guide](./contributing/README.md) | Development environment setup, testing, linting, type-checking, how to write a new analyzer, commit conventions, and the pull request process. |
| [Security Model](./security/README.md) | Detailed explanation of discovery safety, subprocess sandboxing, secret redaction, OSV.dev data minimization, and how to report security issues. |
| [Rules Reference](./rules/README.md) | Complete table of every rule ID produced by RepoLens, grouped by category, with severity and a short description. |
| [Changelog](./changelog/README.md) | Version history in Keep a Changelog format, starting with v0.1.0. |
