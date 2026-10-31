# Changelog

All notable changes to RepoLens are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once released.

RepoLens has **no tagged release yet**: the current package version is `0.1.1.dev0` in development, installable
from this repository, not PyPI. Everything below is therefore unreleased — do not add release/tag
links until a tag actually exists. (The JSON *document* schema is versioned separately as
`1.1.0`; see ADR-006.)

## [Unreleased]

### Added

**Installation reliability (unreleased)**

- A single static development version, reproducible wheel and sdist configuration, distribution
  metadata, platform-specific installation guidance, and Linux/Windows non-editable install checks.
- Documented source-pinning, same-version reinstall behavior, optional tools, and uninstall cleanup.
  No PyPI release or upload is implied.


**Stage 1 — foundation, engine, structure analyzer (October 2026)**

- Pydantic v2 models (`Finding`, `AIAdvisory`, `AnalyzerOutcome`, `DiscoverySummary`,
  `ScanReport`) with deterministic/AI separation, evidence redaction at model entry, and
  auto-generated finding fingerprints; frozen `ScanConfig` with all resource budgets.
- Safe discovery: iterative walk, symlink rejection, platform-scoped `O_NOFOLLOW` reads via
  `RepositoryContext.read_text()`, sensitive-file blocking, root `.gitignore` evaluation, and
  file/byte/depth caps with honest incomplete-coverage accounting.
- `ScanEngine` with a fault-isolated analyzer lifecycle, and the structure analyzer
  (`RL-STRUCT-001`–`012`, `RL-SEC-001`).
- Hardened subprocess execution (`run_safe_command`): `shell=False`, environment allowlist,
  per-stream output caps, whole-tree timeouts (POSIX sessions; Windows process groups +
  `taskkill /T`).

**Stage 2 — practical static analysis (October 2026)**

- Python analyzers: Ruff (`E4,E7,E9,F,B`, `--isolated`) and Bandit (documented skip list);
  JS/TS analyzer: Biome with a RepoLens-generated config. All optional, stub-tested, and run from
  disposable workspaces without loading repository tool configuration.
- Offline dependency hygiene (`RL-DEP-001`–`008`) for Python/npm manifests and lockfiles;
  documentation checks (`RL-DOC-001`–`005`); testing hygiene (`RL-TEST-001`–`005`).
- Opt-in OSV.dev vulnerability lookups (`OSV-<id>`): HTTPS-only, no redirects, coordinate-only
  payloads, explicit incomplete-coverage outcomes on failure.

**Stage 3 — CLI, terminal reporter, versioned JSON (October 2026)**

- `repolens scan [PATH]` (`argparse`, no new dependencies) with `--min-severity`,
  `--max-findings`, `--color`, `--network-checks`, and the documented `0/1/2/3/130` exit-code
  policy, including false-clean protection for partial scans.
- `--format json`: one deterministic, ASCII-only document on stdout
  (`ScanReport.model_dump(mode="json")` + derived `result` verdict), schema `1.1.0`, with
  `parse_json_document` (strict and forward-compatible modes), major-version acceptance policy,
  and unknown-value refusal (`UnsupportedSchemaValueError`). New models/constants:
  `ScanResult`, `ScanStatus`, `IncompleteReason`, `SCHEMA_VERSION`.
- Documentation tree under `docs/` (architecture, ADRs, PRD, contributing, security, rules, this
  changelog), package/test-suite READMEs, root `SECURITY.md`/`CONTRIBUTING.md` entry points, and
  operating-system entries in `.gitignore`.

### Security

- Target code is never executed, imported, or installed; symlinks are never followed; sensitive
  files are never read; subprocesses run shell-free with sanitized environments outside the
  repository; evidence/messages are redacted in text and JSON alike; network checks are opt-in
  and transmit package coordinates only. See [docs/security/README.md](../security/README.md).
