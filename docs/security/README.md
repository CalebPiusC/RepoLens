# Security Model

This document describes the security boundaries that RepoLens enforces when scanning a repository, explains what it does and does not do with the data it reads, and provides guidance for reporting security issues in RepoLens itself.

---

## What RepoLens Does and Does Not Do

**RepoLens does**:

- Read file content from the target repository for static analysis.
- Invoke external linting tools (Ruff, Bandit, Biome) as child processes with the target files as arguments.
- Optionally query the OSV.dev batch API with package names, version strings, and ecosystems (only when `--network-checks` is passed).
- Redact secrets and credentials from all evidence strings before they are stored in a finding.
- Record the presence of sensitive filenames (`.env`, SSH private keys, PEM certificates) without reading their content.

**RepoLens does not**:

- Execute any code, script, or binary from the target repository.
- Import any Python module from the target repository.
- Install any package from the target repository or from any package index.
- Follow symbolic links during file discovery.
- Make network requests in its default configuration.
- Write any data to disk (except temporary directories used by subprocess invocations, which are cleaned up on exit).
- Store reports anywhere; output goes to stdout only.
- Require or use credentials in its default configuration.

---

## Discovery Safety

### Symlink Rejection

The discovery walk never follows symbolic links. When a symlink is encountered (whether pointing to a file or a directory), it is recorded in the `DiscoverySummary` as skipped and excluded from all analysis. This prevents a malicious or misconfigured repository from causing RepoLens to read files outside the repository tree, such as system files or files from other users' home directories.

### O_NOFOLLOW on File Reads

File reads during discovery use `O_NOFOLLOW` at the `open()` call level. This prevents TOCTOU (time-of-check/time-of-use) races: even if a symlink is created between the directory listing step and the file read step, the kernel rejects the open call.

### Sensitive File Detection

Discovery maintains a list of sensitive filename patterns: `.env` files, SSH private key files (`id_rsa`, `id_ed25519`, etc.), PEM certificate and key files, credential store files, and similar. When a file matches a sensitive pattern, its path is recorded in the `DiscoverySummary` but its content is not read. A corresponding finding may be raised by the structure analyzer to alert the user that a sensitive file is present and unignored.

### Resource Limits

Discovery enforces the following limits to prevent resource exhaustion and to bound scan duration:

| Limit | Default |
|---|---|
| Maximum files | 10,000 |
| Maximum size per file | 1 MiB |
| Maximum total bytes across all files | 50 MiB |
| Maximum directory depth | 64 levels |

When any limit is hit, discovery stops and marks the `DiscoverySummary` as truncated. Truncated scans are never reported as clean: the report explicitly records that coverage was incomplete.

### Unreadable Entries

If a directory or file cannot be read due to a permission error or I/O error, the entry is recorded in the `DiscoverySummary` as unreadable and the scan is marked incomplete. RepoLens never silently skips unreadable content and then reports a clean result.

---

## Subprocess Safety

All external tool invocations (Ruff, Bandit, Biome) go through `SubprocessRunner` in `subprocess_runner.py`.

### shell=False

Every `subprocess.run()` call uses `shell=False`. Commands are passed as lists of strings. No shell string interpolation occurs. This means that file paths from the target repository containing shell metacharacters (semicolons, backticks, dollar signs, etc.) cannot cause unintended shell commands to be executed.

### Environment Allowlist

Child processes receive only an explicit allowlist of environment variables. `PATH` is included so that tools can be located. Variables such as `HOME` and `TMPDIR` are included where required for tool operation. No other variables from the parent process environment are inherited. This prevents secrets and credentials that may be present in the CI or developer environment (API keys, database passwords, proxy credentials) from leaking to child processes.

### Process-Group Timeouts

Each subprocess is started in a new process group (a POSIX session group on Linux and macOS, a Windows Job Object on Windows). When the timeout expires, the entire process group is terminated. This prevents orphaned child processes from continuing to consume resources after RepoLens exits or after a timeout is enforced.

### Output Caps

Standard output and standard error from each subprocess are capped at `subprocess_max_output_bytes` (5 MiB by default). Output beyond this cap is discarded. This prevents a misbehaving tool from consuming unbounded memory.

### Disposable Working Directories

External tools are invoked in a temporary working directory, not in the target repository directory. For the JS/TS linter (Biome), RepoLens generates its own Biome configuration in the temporary directory rather than using any `biome.json` that may be present in the target repository. This prevents the target repository's tooling configuration from influencing the analysis.

---

## Secret Redaction

All evidence strings and error messages produced during analysis are passed through the redaction module (`redaction.py`) before they are stored in a `Finding` or included in the report. The redaction module applies pattern matching to detect and replace:

- API keys and bearer tokens.
- Private key PEM blocks.
- JSON Web Tokens (JWTs).
- Credential-bearing URLs (for example, `https://user:password@host/path`).
- Common environment variable assignment patterns for secrets (for example, `SECRET_KEY=...`).

Redaction is applied at the point of data entry into models, not at render time. This means that redacted content never appears in any serialised form of the report, including JSON output.

---

## OSV.dev Data Minimisation

When `--network-checks` is enabled, the advisories analyzer queries `api.osv.dev/v1/querybatch`. The following constraints are applied:

- Only HTTPS is used. HTTP URLs are rejected unconditionally.
- HTTP redirects are not followed.
- The request payload contains only: package `name`, `version`, and `ecosystem`. No file content, no repository path, no repository name, and no user identity are transmitted.
- The response size is capped to prevent unbounded memory consumption from a large response.
- A request timeout is enforced.
- Any network error causes the advisories analyzer to record a `failed` outcome; it does not cause the scan to abort.

---

## Reporting Security Issues

If you discover a security vulnerability in RepoLens itself (not a vulnerability in a repository that RepoLens is scanning), please report it privately rather than opening a public GitHub issue.

Send a description of the issue to the repository maintainer via the GitHub Security Advisories feature: navigate to the repository on GitHub, click "Security", then "Report a vulnerability". Include:

- A clear description of the vulnerability.
- Steps to reproduce it.
- The potential impact.
- If possible, a suggested fix.

The maintainer will acknowledge the report within five business days and will work with you to determine an appropriate disclosure timeline. Public disclosure will not occur before a fix is available.
