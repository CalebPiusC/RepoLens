# ADR-002: Never Follow Symlinks During Discovery

**Status**: Accepted
**Date**: 2024

---

## Context

RepoLens scans arbitrary third-party repositories. A repository may contain symbolic links that point to locations outside the repository tree, including sensitive system files, other user home directories, or device nodes. Following such links during a recursive walk would:

- Allow a malicious or misconfigured repository to cause RepoLens to read files it has no business reading.
- Produce findings that reference files outside the scanned project, confusing the report.
- Enable symlink loop attacks that could cause an infinite traversal.
- Undermine the resource limits (byte caps, file count caps) that bound scan duration and memory use, because those limits are designed around the expected size of the target repository rather than the entire filesystem.

An alternative approach considered was to follow symlinks that resolve to paths within the repository root. This is more permissive and would handle the legitimate use case of a monorepo that symlinks shared code. However, safe resolution of "within the repository root" is non-trivial: it requires resolving the canonical path of the target and checking that it is a strict subdirectory of the canonical path of the root, accounting for race conditions between the resolution check and the actual read.

---

## Decision

RepoLens never follows symlinks. When the discovery walk encounters a symlink (whether to a file or a directory), it records the symlink's path in the `DiscoverySummary` and skips it. The scan is not marked incomplete solely because symlinks were skipped; symlink skipping is considered normal behaviour. However, if a symlink points to something that a user would reasonably expect to be scanned (such as a `src` directory that is itself a symlink), the discovery summary will record that the entry was skipped, and the user can investigate.

All file reads in the discovery path use `O_NOFOLLOW` at the `open()` call level to enforce this policy even in the presence of TOCTOU races: a symlink that did not exist at directory listing time but was created before the open call will be rejected by the kernel.

---

## Consequences

**Positive**:

- No symlink traversal attack is possible. Malicious or accidental symlinks cannot cause RepoLens to read files outside the repository.
- The implementation is simple and unconditional. There are no edge cases around "allowed" versus "disallowed" symlinks.
- TOCTOU safety is enforced at the kernel level via `O_NOFOLLOW`, not just at the policy level.

**Negative**:

- Repositories that use symlinks for legitimate purposes (shared source trees, monorepo patterns) will have those symlinked paths excluded from analysis. This is recorded in the summary but may surprise users.
- A future ADR may revisit this decision for opt-in symlink following with strict canonical path validation, if the demand from monorepo users is significant.
