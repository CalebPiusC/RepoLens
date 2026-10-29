# Security Model

RepoLens is designed to inspect repositories it does not trust. This document states what it does
and does not do, where each guarantee is enforced, and — just as importantly — the limits of
those guarantees. The root README's "Security model" is a summary of this page.

## What RepoLens does and does not do

**RepoLens does:**

- Walk the target tree and read discovered, non-sensitive, size-bounded file contents through
  `RepositoryContext.read_text()` for static checks.
- Invoke already-installed external tools (Ruff, Bandit, Biome) as child processes, passing them
  discovered file paths as arguments.
- Optionally query OSV.dev with package coordinates only, when network checks are explicitly
  enabled.
- Redact recognized secrets from finding evidence and from analyzer/CLI error messages before
  they are stored or printed, in both text and JSON output (JSON is serialized from the same
  models).
- Record the presence of sensitive filenames without reading their contents, and report unignored
  ones as `RL-SEC-001`.

**RepoLens does not:**

- Execute any code, script, or binary from the target repository (no `setup.py`, no npm scripts,
  no test suites, no build steps), or import target Python modules.
- Install or resolve packages from the target repository, or install its own optional tools.
- Follow symbolic links during discovery.
- Make network requests by default, or require credentials, root, or Docker.
- Write into the target repository. The only writes are disposable tool workspaces under the
  system temp directory (including the generated Biome config), which are cleaned up by
  `TemporaryDirectory`; reports go to stdout only.

## Discovery safety (`discovery.py`)

### Symlinks

- The walk uses `entry.is_symlink()` / `follow_symlinks=False`: symlinked files and directories
  are skipped, counted in `DiscoverySummary.skipped_symlink_count`, and their paths are retained
  on `RepositoryContext.skipped_symlinks` (the serialized report carries the count, not the
  paths). Skipped symlinks alone do not make a scan incomplete.
- A symlinked repository root is rejected before scanning (`reject_symlink_root`, default `True`;
  the CLI always uses the default). Programmatic callers may set it to `False`, in which case the
  root is canonicalized with `resolve(strict=True)` and every entry must still resolve inside it.
- Entries that escape the canonical root abort discovery (`DiscoveryAbortedError`).

### File reads and TOCTOU scope

Contents are read only through `RepositoryContext.read_text()`, which:

1. Rejects unsafe relative paths (absolute, backslashes, NUL, `..`).
2. Requires the file to be part of safe discovery, non-sensitive, and within the per-file size
   cap.
3. Refuses if the target is now a symlink, and requires the resolved path to stay inside the
   canonical root.
4. Opens with `os.O_RDONLY | O_NOFOLLOW` **where `O_NOFOLLOW` exists** (POSIX: Linux, macOS). A
   symlink swapped in after listing then fails at `open()` (`ELOOP`). On platforms without
   `O_NOFOLLOW` (notably Windows) steps 1–3 still apply, but there is no kernel-level guarantee
   against a swap in the remaining race window.

Discovery itself does not read file contents except the root `.gitignore` (through the same
path). External tools open the files they receive with their own I/O; they are given only paths
that already passed discovery (never sensitive, oversized, ignored, or symlinked entries), and
tool-reported paths are accepted only if they resolve back inside the root.

### Sensitive files

`classify_sensitive_file()` covers `.env` and `.env.*` (except safe templates: `.env.example`,
`.env.sample`, `.env.template`, `.env.dist`, `.env.defaults`, `.env.schema`), `.pypirc`,
`.netrc`, `.git-credentials`, SSH private keys (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`),
`credentials.json`, `client_secret.json`, `.streamlit/secrets.toml`, `service-account*.json`,
and extensions `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.kdbx`. Matching files are
counted in `sensitive_files_detected`; `read_text()` and tool file-selection exclude them.

### `.gitignore`, exclusions, and resource limits

- Only the **root** `.gitignore` is evaluated (a deterministic built-in matcher, including
  negations and directory-only patterns). Nested `.gitignore` files are discovered as ordinary
  files but not applied.
- Convention directories (`.git`, `node_modules`, `.venv`, `dist`, build/cache outputs, and
  similar; see `DEFAULT_EXCLUDED_DIRS`) are never entered.
- Defaults: 10,000 files, 1 MiB per file, 50 MiB total counted bytes, 64-level walk depth.
  Reaching a file/byte cap, skipping over-depth subtrees, and unreadable directories/entries are
  all recorded in `DiscoverySummary` and make the scan incomplete (exit `3`, or `1` if findings
  take precedence) — partial coverage is never reported as clean.

## Subprocess safety (`subprocess_runner.py`, `analyzers/tooling.py`)

All tool execution goes through `run_safe_command()`:

- **`shell=False`, always.** Arguments are a validated list; a shell string is rejected.
  `subprocess.Popen` is used for the tool itself (the one `subprocess.run()` call in the module
  is the fixed-argument Windows `taskkill` helper). Repository file paths containing shell
  metacharacters are therefore inert.
- **Environment allowlist.** Children inherit only `PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `HOME`,
  `TMPDIR`, `TEMP`, `TMP`, `SYSTEMROOT`, and `PATHEXT` when present, plus forced values
  (`CI=1`, `NO_COLOR=1`, `TERM=dumb`, `GIT_TERMINAL_PROMPT=0`, `PIP_DISABLE_PIP_VERSION_CHECK=1`,
  `PYTHONDONTWRITEBYTECODE=1`, `NODE_NO_WARNINGS=1`). Host secrets in other variables do not
  propagate. Explicit `extra_env` additions are validated (no NUL/`=` in keys).
- **Executable resolution** happens on that sanitized `PATH`. Availability probing runs only the
  tool's `--version` in a disposable workspace.
- **Working directory:** callers pass a disposable workspace outside the repository
  (`tooling.tool_workspace()`); `run_safe_command` requires a real, non-symlink directory.
  Repository tool configuration is not loaded (Ruff `--isolated`; generated Biome config via
  `--config-path`; project config presence is reported, not used).
- **Timeouts kill the whole tree.** POSIX: new session (`start_new_session`) and `killpg`
  `SIGTERM` → `SIGKILL`. Windows: `CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW` plus
  `taskkill /F /T /PID` with a `kill()` fallback. RepoLens does **not** use Windows Job Objects.
- **Output caps:** stdout and stderr are each capped at `subprocess_max_output_bytes` (5 MiB by
  default) on reader threads; truncation is flagged rather than growing memory without bound.
  Stdin is `DEVNULL`.

## Secret redaction (`redaction.py`)

`redact_secrets()` scrubs PEM private-key material; GitHub, AWS, Google/Gemini, Anthropic/OpenAI,
Stripe, Slack, PyPI, and npm token shapes; JWTs; credential-bearing URLs; `Authorization`
values; and generic secret assignments (quoted and unquoted), preserving known safe placeholders.
It is applied by model validators to `Finding.evidence` (truncated to 500 chars) and
`AnalyzerOutcome.message`, and explicitly to CLI diagnostics and subprocess stderr surfaces.

Scope note: redaction covers those evidence/message fields. Finding titles, explanations, and
recommendations are constructed by RepoLens (or from bounded tool diagnostics) rather than copied
from sensitive files — sensitive files are never read at all, which is the primary control.
Redaction is best-effort pattern matching, not a formal guarantee that no secret-shaped string
can ever appear; treat reports as sensitive until reviewed.

## OSV.dev data minimization (`osv.py`, `analyzers/advisories.py`)

Enabled only by `--network-checks` / `ScanConfig(enable_network_checks=True)`:

- HTTPS only to the constant `https://api.osv.dev` origin (`/v1/querybatch`,
  `/v1/vulns/<id>`); paths are validated and redirects are rejected, never followed.
- Payloads contain only package `name`, `version`, and `ecosystem` — no file paths, contents,
  repository names, environment, or credentials. A fixed `User-Agent` is sent.
- Bounded by per-request timeout (default 10 s), a total lookup budget, response-size cap
  (default 2 MiB, checked against `Content-Length` and actual bytes), batches of 100, and
  package/advisory caps (defaults 300/50). Packages beyond the cap mark coverage partial.
- Outcomes are explicit: timeout → `timed_out`; connection/HTTP failure after the check started
  → `unavailable` with `coverage_incomplete=True` (scan incomplete, never a silent clean);
  unreadable payloads → `failed`. A vulnerability is reported only with an advisory ID returned
  by OSV.dev; unrated advisories are medium/low-confidence and labelled estimated.

## Analyzer fault isolation

With `fail_fast=False` (default, and always in the CLI), one analyzer's failure, timeout, or
broken probe is recorded as its outcome and the rest of the scan continues; completeness is then
reflected in `result.is_complete` / the exit code rather than hidden. Analyzers that never
started (`unavailable` without `coverage_incomplete`, or `skipped`) do not by themselves make a
scan incomplete.

## Reporting a vulnerability in RepoLens

Please do **not** open a public issue for a vulnerability in RepoLens itself. Report it privately
to the repository owner through GitHub (the repository's **Security** tab → *Report a
vulnerability*, when private reporting is available there), including a description, reproduction
steps, impact, and a suggested fix if you have one. Coordinated disclosure — keeping details
private until a fix is available — is appreciated. This policy makes no response-time commitment.

> Maintainer note: as of this writing, GitHub private vulnerability reporting is **not** enabled
> on `CalebPiusC/RepoLens`, so the button above will not appear until the owner enables it
> (Settings → Security → Private vulnerability reporting). Enabling it is the recommended way to
> make these instructions actionable.
