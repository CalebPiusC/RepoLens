# Changelog

All notable changes to RepoLens are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). RepoLens adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

No unreleased changes at this time.

---

## [0.1.0] - 2024

### Added

**Stage 1: Foundation, Engine, and Structure Analyzer**

- `ScanEngine` in `engine.py`: orchestrates discovery, analyzer execution with per-analyzer fault isolation, and report assembly.
- `ScanConfig` in `config.py`: Pydantic v2 model defining all resource limits and feature flags, with defaults of 10,000 max files, 1 MiB per-file cap, 50 MiB total cap, 30-second subprocess timeout, and network checks disabled.
- `discovery.py`: safe iterative DFS repository walk with symlink rejection, `O_NOFOLLOW` reads, sensitive file detection, per-file and total byte caps, 64-level depth cap, and `.gitignore` evaluation.
- `models.py`: core Pydantic v2 models: `Finding` (with SHA-256 fingerprint auto-generation and automatic evidence redaction), `AIAdvisory`, `AnalyzerOutcome`, `DiscoverySummary`, and `ScanReport`.
- `analyzers/base.py`: `BaseAnalyzer` abstract base class defining `is_applicable()`, `check_availability()`, `skip_reason()`, `analyze()`, `coverage_partial()`, and `completion_message()`.
- `analyzers/structure.py`: structure and hygiene analyzer producing rules `RL-STRUCT-001` through `RL-STRUCT-012`. Checks for LICENSE, README, `.gitignore` coverage, unignored secrets and vendor directories, manifests, lockfiles, binary bloat, and `.gitignore` incorrectly excluding committed files.
- `exceptions.py`: custom exception hierarchy for scan-level and discovery-level errors.
- `redaction.py`: secret redaction module scrubbing API keys, tokens, PEM private keys, JWTs, and credential-bearing URLs from evidence strings.
- `subprocess_runner.py`: `SubprocessRunner` with `shell=False`, environment allowlist, per-output-stream byte caps, and cross-platform process-group timeout enforcement (POSIX session groups on Linux/macOS, Job Objects on Windows).

**Stage 2: Python/JS-TS Analyzers, Dependency Checks, Documentation, and Testing Checks**

- `analyzers/python_lint.py`: runs Ruff (`E4`, `E7`, `E9`, `F`, `B` rule groups) and Bandit (with skip list `B101`, `B105`, `B106`, `B110`, `B112`, `B311`, `B404`, `B603`, `B607`). Both tools use `shell=False`, isolated environments, and disposable working directories.
- `analyzers/jsts_lint.py`: runs Biome using a RepoLens-generated configuration (recommended rules, VCS disabled) in a temp directory. Reports findings as `BIOME-<rule>`.
- `analyzers/dependencies.py`: parses Python manifests (`pyproject.toml` supporting PEP 621, Poetry, and PEP 735; `Pipfile`; `setup.cfg`; `requirements*.txt`) and lockfiles (`poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`). Parses npm manifests (`package.json`) and lockfiles (`package-lock.json` v1/v2/v3, `npm-shrinkwrap.json`, `yarn.lock` classic and Berry, best-effort `pnpm-lock.yaml`). Produces rules `RL-DEP-001` through `RL-DEP-008`.
- `analyzers/documentation.py`: checks manifest/README/LICENSE cross-references, README relative link validity, and SPDX license identifier consistency. Produces rules `RL-DOC-001` through `RL-DOC-005`.
- `analyzers/testing.py`: checks for test file presence, test runner configuration, coverage configuration, and pytest declared as a dependency. Produces rules `RL-TEST-001` through `RL-TEST-005`.
- `analyzers/advisories.py`: opt-in OSV.dev integration. Sends only `name`, `version`, and `ecosystem` to `api.osv.dev/v1/querybatch` over HTTPS. Enforces redirect rejection, response size caps, and request timeouts.
- `osv.py`: OSV.dev API client with data minimisation and HTTP safety constraints.
- `dependencies.py` (top-level): shared dependency parsing utilities used by the dependencies analyzer.

**Stage 3: CLI and Terminal Reporter**

- `cli.py`: `argparse`-based CLI. Command: `repolens scan [PATH]`. Options: `--min-severity`, `--max-findings`, `--color`, `--network-checks`, `--version`. Exit codes: 0 (clean), 1 (findings), 2 (usage error), 3 (operational/incomplete), 130 (interrupted).
- `__main__.py`: enables `python -m repolens` invocation.
- `reporting.py`: terminal reporter with `RenderOptions` (color, min_severity, max_findings). `evaluate()` derives the verdict; `render_report()` produces the formatted string.
- Full test suite in `tests/` covering unit, integration, and security scenarios across Python 3.11, 3.12, and 3.13 on Ubuntu and Windows.
- CI workflow in `.github/workflows/ci.yml` running Ruff lint, Ruff format check, mypy strict, and pytest with coverage.
- `py.typed` marker enabling type-checking by downstream consumers.
- `pyproject.toml` with Hatch build backend, full project metadata, and development dependency groups.

### Security

- Symlink rejection during discovery prevents path traversal attacks via crafted repositories.
- `O_NOFOLLOW` on all file reads prevents TOCTOU race conditions.
- `shell=False` and subprocess environment allowlist prevent shell injection and credential leakage to child processes.
- Evidence redaction prevents secrets in scanned repositories from appearing in reports.
- OSV.dev queries transmit only package-level metadata with no file content or user identity.
- OSV.dev network checks are opt-in; no network requests are made in the default configuration.

[Unreleased]: https://github.com/CalebPiusC/RepoLens/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CalebPiusC/RepoLens/releases/tag/v0.1.0
