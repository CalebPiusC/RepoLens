# ADR-003: Always Use `shell=False` and a Sanitized Environment for Subprocesses

**Status:** Accepted
**Recorded:** 2026-10-29, retrospectively (implemented in Stages 1–2, October 2026)

## Context

The Ruff, Bandit, and Biome analyzers pass target-repository file paths to external tools. With
`shell=True`, a crafted path could inject shell syntax. With a default inherited environment, CI
or developer secrets (API keys, tokens, credentials) would leak into child processes that process
untrusted input. Tools also need bounded time/output and must not load the target's own tool
configuration.

## Decision

Every tool invocation goes through `run_safe_command()` in `subprocess_runner.py` (there is no
`SubprocessRunner` class), which unconditionally:

1. Executes with `subprocess.Popen(..., shell=False)` and a validated argument list; passing a
   shell string raises `SubprocessExecutionError`. The executable is resolved on the sanitized
   `PATH`.
2. Builds the child environment from an allowlist (`PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `HOME`,
   `TMPDIR`, `TEMP`, `TMP`, `SYSTEMROOT`, `PATHEXT`) plus forced safe values (`CI`, `NO_COLOR`,
   `TERM=dumb`, `GIT_TERMINAL_PROMPT`, pip/Python/Node quieting flags). Additional variables
   require an explicit, validated `extra_env`.
3. Requires a real, non-symlink working directory. Analyzer code (via
   `analyzers/tooling.tool_workspace()`) passes a disposable directory outside the repository;
   the runner itself does not choose the directory.
4. Caps stdout and stderr **independently** at `subprocess_max_output_bytes` and enforces a hard
   timeout that terminates the whole tree: POSIX new session + `killpg` (`SIGTERM` then
   `SIGKILL`); Windows `CREATE_NEW_PROCESS_GROUP` + `taskkill /F /T /PID` (with a `kill()`
   fallback). No Windows Job Objects are used.

## Consequences

Positive:

- Shell injection through repository paths is structurally impossible; parent secrets cannot leak
  by inheritance; timed-out tools cannot orphan grandchildren (including through Windows `.cmd`
  shims); allowlist additions are deliberate, reviewable code changes.

Negative:

- A tool needing an unusual environment variable will not see it until someone adds it to the
  allowlist or passes `extra_env`.
- Termination and executable probing need platform-specific code paths (POSIX sessions vs Windows
  process groups/`taskkill`), which the test suite exercises via stub launchers on both.
