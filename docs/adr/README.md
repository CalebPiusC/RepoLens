# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for RepoLens. Each ADR documents a significant design choice: the context that prompted it, the decision that was made, and the consequences that follow from it. ADRs are written at decision time and are not revised after acceptance except to record supersession.

## Index

| ID | Title | Status |
|---|---|---|
| [ADR-001](./ADR-001-pydantic-v2-models.md) | Use Pydantic v2 for all data models | Accepted |
| [ADR-002](./ADR-002-no-symlink-following.md) | Never follow symlinks during discovery | Accepted |
| [ADR-003](./ADR-003-shell-false-subprocess.md) | Always use `shell=False` and a sanitised environment for subprocesses | Accepted |
| [ADR-004](./ADR-004-osv-network-opt-in.md) | Make OSV.dev network checks opt-in rather than default | Accepted |
| [ADR-005](./ADR-005-deterministic-ai-separation.md) | Keep deterministic findings strictly separate from AI advisories | Accepted |
