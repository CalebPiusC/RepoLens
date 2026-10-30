# ADR-002: Never Follow Symlinks During Discovery

**Status:** Accepted
**Recorded:** 2026-10-29, retrospectively (implemented in Stage 1, October 2026)

## Context

RepoLens scans arbitrary third-party repositories. A symlink can point outside the tree
(system files, other users' data, device nodes), create traversal loops, or defeat the resource
caps that assume repository-sized input. Following only links that resolve inside the root was
considered, but doing that race-free requires canonical-path validation at every read, for a
legitimate use case (symlinked shared/monorepo trees) that can be revisited if demand appears.

## Decision

Discovery never follows symlinks:

- Symlinked files/directories are skipped. Their paths are kept on
  `RepositoryContext.skipped_symlinks`; the serialized `DiscoverySummary` records the count
  (`skipped_symlink_count`). Skipped symlinks alone do not mark a scan incomplete — but content
  reachable *only* through a symlink is simply not analyzed, which the count makes visible.
- A symlinked repository root is rejected by default (`ScanConfig.reject_symlink_root=True`; the
  CLI always uses the default). Library callers who disable it still get a canonicalized root and
  per-entry root-escape checks.
- Contents are read only via `RepositoryContext.read_text()`, which re-checks symlink/root
  constraints and opens with `O_NOFOLLOW` where available (POSIX), so a link swapped in after
  listing fails at `open()` there. On platforms without `O_NOFOLLOW` (notably Windows) the
  pre-open checks apply without the kernel-level guarantee; see ADR-003's sibling concern in the
  [security model](../security/README.md#file-reads-and-toctou-scope).

## Consequences

Positive:

- No symlink traversal outside the repository, no link-loop traversal, no cap evasion via links.
- One unconditional rule; no "allowed link" edge cases.

Negative:

- Repositories that symlink source trees have those paths excluded (visible via
  `skipped_symlink_count`, but potentially surprising).
- The POSIX/Windows TOCTOU asymmetry above must be documented honestly rather than papered over.
- An opt-in, canonically-validated link-following mode would need a superseding ADR.
