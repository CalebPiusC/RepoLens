# Architecture Decision Records

Each ADR records one significant design decision: the context, the decision, and its
consequences.

ADR-001 through ADR-005 were implemented during Stages 1–2 (October 2026) and written down
retrospectively when this documentation tree was added; their dates say so explicitly rather than
claiming they were authored at decision time. ADR-006 was recorded with the JSON output work it
describes. An ADR, once accepted, is not edited to change the decision — a later ADR supersedes
it and both cross-reference each other.

## Index

| ID | Title | Status |
| --- | --- | --- |
| [ADR-001](./ADR-001-pydantic-v2-models.md) | Use Pydantic v2 for all data models | Accepted |
| [ADR-002](./ADR-002-no-symlink-following.md) | Never follow symlinks during discovery | Accepted |
| [ADR-003](./ADR-003-shell-false-subprocess.md) | Always use `shell=False` and a sanitized environment for subprocesses | Accepted |
| [ADR-004](./ADR-004-osv-network-opt-in.md) | Make OSV.dev network checks opt-in rather than default | Accepted |
| [ADR-005](./ADR-005-deterministic-ai-separation.md) | Keep deterministic findings strictly separate from AI advisories | Accepted |
| [ADR-006](./ADR-006-versioned-json-output.md) | Emit one versioned JSON document (`--format json`, schema `1.1.0`) | Accepted |
