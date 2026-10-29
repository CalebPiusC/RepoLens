# Product Requirements Document

**Product:** RepoLens
**Package version:** `0.1.0` (unreleased; no tagged release yet — install from the repository)
**Status:** Alpha. Stages 1–3 are complete, including the versioned JSON output (schema `1.1.0`).

This PRD describes intent and scope. Where it touches implemented behavior, the code, tests, and
root README are authoritative; targets below are goals, not measured guarantees, unless a test
enforces them.

## Product vision

RepoLens answers, for developers, CI pipelines, and security reviewers: "what is wrong with this
repository — structurally, in its dependencies, docs, tests, and code quality — *before* I run or
install it?" It is trustworthy against repositories you do not control because it is fully static:
it reads files, never executes them, and never installs anything from the target.

## Target users

- **Developers** maintaining Python or JS/TS projects, run locally or in CI to catch hygiene,
  configuration, dependency, and lint/security issues early.
- **CI pipelines** gating on documented exit codes (`0/1/2/3/130`) or consuming
  `--format json` (single document on stdout, `result` verdict included) as an artifact or pipe
  input — no service account, Docker, or network needed by default.
- **Security reviewers** evaluating third-party code before adoption: committed secrets, missing
  lockfiles/licenses, and (with `--network-checks`) known-vulnerable locked dependencies.

## Core requirements (implemented, Stages 1–3)

RepoLens must:

- Accept a repository path and produce a `ScanReport` of findings with stable rule IDs,
  categories, severities, confidences, locations, explanations, recommendations, and verification
  steps (see the [rules reference](../rules/README.md)).
- Discover files within configurable resource limits, honoring the root `.gitignore` and built-in
  directory exclusions, never following symlinks or reading sensitive files.
- Run structure, dependency, documentation, and testing analyzers offline; Ruff/Bandit (Python)
  and Biome (JS/TS) when already installed; and OSV.dev lookups only on explicit opt-in.
- Isolate analyzer failures and report coverage honestly: a partial scan is *incomplete* and
  never exits `0`.
- Redact recognized secrets from evidence and error messages in every output format.
- Emit a versioned JSON document (`--format json`, schema `1.1.0`) whose `result` member always
  agrees with the exit code, with a documented compatibility/version-acceptance policy and a
  maintained parser (`parse_json_document`, strict and forward-compatible modes).
- Run on Python 3.11–3.13. CI exercises Ubuntu (full quality gates) and Windows (test suite);
  macOS is a supported-by-design platform (POSIX code paths) without a dedicated CI job today.
- Pass Ruff lint/format and strict mypy over `src` and `tests`.

RepoLens must not:

- Execute, import, build, test, or install target-repository code or dependencies; follow
  symlinks; load target tool configuration; access the network without opt-in; require root,
  Docker, or credentials in default mode; or present AI-generated content as deterministic
  findings (Stage 4 advisories remain a separate, future, opt-in type).

## Non-functional requirements

- **Bounded work:** discovery, per-tool, subprocess, and network budgets in `ScanConfig` bound
  time and memory regardless of target size; each tool call has its own timeout (30 s default) so
  one slow tool cannot stall a scan indefinitely. (No end-to-end wall-clock SLO is currently
  measured or enforced by tests.)
- **Determinism:** same content + options ⇒ same findings, order, and fingerprints; JSON is
  byte-identical except `scanned_at`/`duration_ms`.
- **Portability:** no C extensions in RepoLens itself; optional tools degrade to `unavailable`
  outcomes instead of failures.
- **Observability:** every analyzer records status, duration, and coverage flags; discovery
  records skip/truncation/unreadable counts; documents carry `schema_version` separately from
  `repolens_version`.

## Out of scope (current roadmap)

- Automatic remediation/fixes or PR creation; dynamic/runtime analysis; actually running tests or
  measuring coverage (only their presence/configuration is checked).
- Languages beyond Python and JavaScript/TypeScript.
- Per-rule suppression (inline comments or ignore files) and user-defined rules — neither exists
  today; `--min-severity` is the only threshold control.
- Markdown report output (future work; text and JSON exist), GitHub-archive/ZIP scanning and the
  web UI (Stage 5), Gemini advisories (Stage 4), container isolation (Stage 6), issue-tracker
  integrations.

## Success criteria

- Full suite green in CI on Ubuntu + Windows × Python 3.11/3.12/3.13, with Ruff and strict mypy
  clean — including the repository self-scan test (RepoLens scanning itself reports nothing at or
  above `low`, except the intentional `RL-DEP-005` info note).
- JSON documents round-trip through `parse_json_document` in both modes; unknown-member tolerance
  and unknown-value refusal are covered by `tests/unit/test_json_output.py`; document and exit
  code never disagree in CLI tests.
- No test requires network access or installed Ruff/Bandit/Biome (stub executables and in-memory
  OSV transports only), and no finding evidence in the suite contains an unredacted secret fixture.
- A scan that could not see the whole repository is never reported clean, in text, JSON, or exit
  code.
