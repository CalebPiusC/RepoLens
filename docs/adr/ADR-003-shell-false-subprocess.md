# ADR-003: Always Use `shell=False` and a Sanitised Environment for Subprocesses

**Status**: Accepted
**Date**: 2024

---

## Context

Three analyzers in RepoLens invoke external tools: `python_lint.py` calls Ruff and Bandit, and `jsts_lint.py` calls Biome. These tools receive file paths from the target repository as arguments.

When Python's `subprocess` module is called with `shell=True`, the command string is passed to the system shell (`/bin/sh` on POSIX, `cmd.exe` on Windows). This creates two classes of risk:

1. **Shell injection**: If any part of the command string is constructed from user-controlled data (such as file paths from the target repository), a crafted path containing shell metacharacters could cause the shell to execute unintended commands.
2. **Environment leakage**: A child process inherits the full environment of the parent by default. This environment may contain API keys, credential tokens, database connection strings, proxy passwords, or other sensitive values passed to RepoLens by its calling context (CI system, developer shell, etc.). A child process that logs its environment, or a tool that uses certain environment variables in unexpected ways, could expose these values.

Both risks are present when scanning untrusted repositories. File paths inside a repository cannot be assumed to be safe strings.

---

## Decision

All subprocess calls in RepoLens go through `SubprocessRunner` in `subprocess_runner.py`. This module enforces two invariants unconditionally:

1. `shell=False` on every `subprocess.run()` / `subprocess.Popen()` call. Commands are passed as lists of strings. No shell interpolation occurs.
2. The child process environment is constructed from an explicit allowlist of variable names. `PATH` is included so that tools can be located. Variables such as `HOME` and `TMPDIR` are included where needed for tool operation. No other variables from the parent environment are inherited.

In addition, `SubprocessRunner` runs each tool in a disposable temporary working directory (not the target repository directory), caps output at `subprocess_max_output_bytes`, and kills the entire process group on timeout.

---

## Consequences

**Positive**:

- Shell injection via crafted file paths is structurally impossible because no shell is involved.
- Parent process credentials and secrets cannot leak to child processes through environment inheritance.
- Timeout enforcement kills the entire process group, not just the direct child, preventing orphaned subprocesses from consuming resources after RepoLens exits.
- The allowlist approach means that adding a new environment variable to the child requires an explicit code change, making leakage decisions visible in code review.

**Negative**:

- Some tools rely on environment variables that are not in the allowlist (for example, tool-specific config paths or proxy settings). Such variables must be explicitly added to the allowlist when a new tool is integrated, which requires investigation of each tool's behaviour.
- On Windows, process group termination requires a Job Object approach rather than POSIX session groups. This adds platform-specific code to `SubprocessRunner`.
- Developers running RepoLens in environments with non-standard `PATH` configurations may need to ensure that Ruff, Bandit, and Biome are discoverable on the allowed `PATH`.
