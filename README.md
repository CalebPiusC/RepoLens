# RepoLens
An open-source repository health checker for Python and JavaScript/TypeScript projects.

![RepoLens — See the health of your codebase.](assets/social-preview.png)

RepoLens helps developers identify, understand, and fix repository hygiene, configuration, code quality, dependency, and security issues before publishing or deploying a project.

## Current Status — Stage 2 (Static Analysis)

RepoLens is built in incremental stages. Stages 1 and 2 are complete:

**Stage 1 — foundation and shared engine**

- **Validated report schema (`repolens.models`):** Strict Pydantic v2 models (`Finding`, `AIAdvisory`, `AnalyzerOutcome`, `ScanReport`) with structural separation between deterministic scanner findings and future opt-in AI advisories.
- **Safe repository discovery (`repolens.discovery`):** Canonical root enforcement, symlink escape rejection, TOCTOU `O_NOFOLLOW` file reads, sensitive-file read blocks (`.env*`, private keys, credential files), `.gitignore` evaluation, and file/byte resource caps.
- **Evidence secret redaction (`repolens.redaction`):** Automatic scrubbing of API keys, tokens, private keys, JWTs, and credential URLs before evidence or error messages enter a report.
- **Hardened subprocess runner (`repolens.subprocess_runner`):** `shell=False` execution, allowlist-only environment sanitization, output byte caps, and process-group timeouts for external static analyzers.
- **Shared scan engine and structure analyzer (`repolens.engine`, `repolens.analyzers.structure`).**

**Stage 2 — practical static analysis**

- **Python (`Ruff`, `Bandit`)** lint/syntax/quality diagnostics and common security anti-patterns, normalized into the shared `Finding` model.
- **JavaScript/TypeScript (`Biome`)** lint diagnostics with a hardened, RepoLens-owned configuration.
- **Offline dependency hygiene** for Python and npm manifests and lockfiles, plus **opt-in OSV.dev** known-vulnerability lookups.
- **Documentation and testing hygiene** checks (README/license cross-references, test presence, runner/coverage configuration).
- **Fault-isolated analyzer lifecycle** distinguishing completed, skipped, unavailable, timed-out, and failed checks.

### Roadmap

- **Stage 1 (Complete):** Project foundation, shared analysis engine, structure analyzer, and test suite.
- **Stage 2 (Complete):** Python (`Ruff`, `Bandit`) and JavaScript/TypeScript (`Biome`) analyzer adapters, manifest/lockfile and OSV dependency checks, documentation and static test checks.
- **Stage 3:** Command-line interface (`repolens scan`) and Terminal, JSON, and Markdown reporters.
- **Stage 4:** Strict opt-in Gemini advisory explanations.
- **Stage 5:** FastAPI + HTML/HTMX web interface for GitHub archive and ZIP scanning.
- **Stage 6:** Container isolation hardening, and public beta.

## Requirements

- Python `>= 3.11`

RepoLens itself has no runtime requirement on Ruff, Bandit, Biome, Node.js, or network access. External tools and OSV.dev are strictly optional.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Optional external tools

RepoLens never installs tools for you and never installs anything from the scanned repository. Install these once on the machine that runs the scan if you want the corresponding analyzer:

```bash
# Python lint + security checks (already included in the `dev` extra)
pip install "repolens[tools]"          # Bandit + Ruff
# or explicitly:
pip install bandit ruff

# JavaScript/TypeScript lint checks (Node.js required)
npm install --global @biomejs/biome
```

Availability is detected with a sanitized `PATH`. Missing tools are reported as `unavailable` analyzer outcomes and never abort the scan:

```text
ruff-python-lint        unavailable   `ruff` executable was not found on PATH (optional tool not installed).
bandit-python-security  unavailable   `bandit` executable was not found on PATH (optional tool not installed).
```

## Supported checks

Every finding carries a stable rule ID, a location, deterministic provenance (`FindingSource`), evidence, explanation, recommendation, and a verification step. Rule IDs prefixed with a tool name preserve that tool's own rule code.

| Rule ID | Category | Severity | Check |
| --- | --- | --- | --- |
| `RL-STRUCT-001` … `RL-STRUCT-011` | structure | info–high | LICENSE, README, `.gitignore` coverage, unignored secrets/vendor dirs, manifests, lockfiles, binary bloat (Stage 1) |
| `RL-STRUCT-012` | structure | low | `.gitignore` excludes lockfiles or test directories that should be committed |
| `RL-DEP-001` | dependencies | medium | Malformed dependency lockfile |
| `RL-DEP-002` | dependencies | medium | Invalid PEP 508 requirement in a requirements file |
| `RL-DEP-003` | dependencies | low | npm dependency declared but not present in the lockfile |
| `RL-DEP-004` | dependencies | medium | Locked npm version outside the declared semver range (only provable simple ranges) |
| `RL-DEP-005` | dependencies | info | Python runtime dependencies are unpinned and not locked |
| `RL-DEP-006` | dependencies | medium | Conflicting exact pins for the same Python distribution |
| `RL-DEP-007` | dependencies | info | Lockfile format RepoLens cannot parse (audit coverage gap) |
| `RL-DEP-008` | dependencies | medium | Malformed non-root dependency manifest |
| `RL-DOC-001` / `RL-DOC-002` | documentation | medium | Manifest references a missing README or license file |
| `RL-DOC-003` | documentation | low | README relative link points at a missing path |
| `RL-DOC-004` | documentation | low | Declared SPDX license disagrees with LICENSE file content |
| `RL-DOC-005` | documentation | low | Manifests declare incompatible licenses |
| `RL-TEST-001` / `RL-TEST-002` | testing | medium | No recognizable Python / JS-TS tests despite source files |
| `RL-TEST-003` | testing | low | Tests exist but no runner configuration is detected |
| `RL-TEST-004` | testing | info | Coverage tooling declared but never configured |
| `RL-TEST-005` | testing | low | `pytest` imported by tests but not declared as a dependency |
| `RUFF-<code>` | code quality | low–high | Ruff diagnostics (`invalid-syntax` and `E9*` are high severity) |
| `BANDIT-<id>` | security | low–high | Bandit security checks; severity/confidence and CWE are preserved |
| `BIOME-<rule>` | code quality / security | info–medium | Biome lint diagnostics |
| `OSV-<advisory-id>` | security | low–critical | Known vulnerability from OSV.dev for a locked package version |

### Python analysis details

- Ruff runs with `--isolated --no-cache --no-fix` and a fixed rule selection (`E4,E7,E9,F,B`) so repository configuration cannot silently disable checks.
- Bandit runs from a disposable working directory with an explicit `--skip` list for checks that are dominated by false positives in application code and tests: `B101`, `B105`, `B106`, `B110`, `B112`, `B311`, `B404`, `B603`, `B607`. Use `ruff`'s `S` rules or a dedicated security review if you need them.
- Both tools receive an explicit list of repository files that already passed discovery (no sensitive files, no oversized files, no ignored paths, no symlinks).

### JavaScript/TypeScript analysis details

- Biome is used only if an executable is already available; RepoLens never runs `npm install`, `pnpm install`, or any repository script.
- RepoLens generates its own Biome configuration (`recommended` rules, VCS/ignore-file disabled) in a temporary directory and passes it via `--config-path`, so project configuration (including Biome plugins) is never loaded. Presence of project configuration is reported in the analyzer outcome message.
- Biome's experimental JSON reporter is parsed defensively; malformed output becomes a `failed` outcome rather than a crash.

### Dependency analysis details

Parsed manifests and lockfiles:

| Ecosystem | Manifests | Lockfiles / pins |
| --- | --- | --- |
| Python | `pyproject.toml` (PEP 621, Poetry, PEP 735 groups), `Pipfile`, `setup.cfg`, `requirements*.txt` / `requirements*.in` | `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, fully pinned requirements |
| npm | `package.json` (`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`) | `package-lock.json` (v2/v3 and v1), `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), best-effort `pnpm-lock.yaml` |

Notes and limitations:

- `setup.py` is **never executed**, so projects that declare dependencies only in `setup.py` are not dependency-audited. `bun.lock`/`bun.lockb` are detected but not parsed (`RL-DEP-007`).
- `pnpm-lock.yaml` parsing is best-effort and marked incomplete, so pnpm projects are not checked for manifest/lockfile drift.
- Semver range checks only cover provable simple constraints (`^`, `~`, `=`, exact). Complex ranges, `||`, aliases, and workspace/file/git specifiers are skipped instead of guessed.
- Paths are matched per directory, so monorepo workspaces are compared against the lockfile next to their own `package.json`.

## Network-dependent behavior

Known-vulnerability lookups are **disabled by default**. Enable them explicitly:

```python
from pathlib import Path
from repolens import ScanConfig, ScanEngine

engine = ScanEngine(config=ScanConfig(enable_network_checks=True))
report = engine.scan(Path("."))
```

What this does:

- Sends **only** package name, version, and ecosystem (e.g. `{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}`) to `https://api.osv.dev/v1/querybatch` and `https://api.osv.dev/v1/vulns/<id>`.
- Never sends file paths, source code, repository names, environment variables, or credentials.
- Enforces HTTPS only, rejects redirects, applies request timeouts, a hard response-size ceiling, batch limits (100 coordinates per request), a package cap, and an advisory cap.
- Reports service problems explicitly instead of guessing: timeouts produce a `timed_out` outcome, connection/HTTP errors produce `unavailable`, and unreadable payloads produce `failed`.
- Never labels a dependency vulnerable without an advisory ID returned by OSV.dev. When OSV publishes no severity, the finding is marked medium severity with low confidence, and the explanation says the rating is estimated.

Disabling network checks (default) still runs every offline check. Outcome messages state why the OSV analyzer was skipped.

## Security model

RepoLens is a static-analysis tool:

- It never executes code from the target repository (no `setup.py`, no npm scripts, no test suites, no build steps).
- It never installs packages from the target repository or resolves its dependencies.
- Subprocesses are invoked with structured argument lists (`shell=False`), a sanitized environment (host secrets removed), a disposable working directory outside the repository, and both time and output-size limits.
- Repository-provided tool configuration (`.ruff.toml`, `[tool.ruff]` in `pyproject.toml`, `.bandit`, `biome.json`/`biome.jsonc`) is not trusted or loaded.
- Sensitive files are never read; evidence and error text pass through secret redaction before entering a report.
- Tool-reported paths are resolved and rejected unless they stay inside the repository root; symlinks are never followed.
- Untrusted JSON/TOML/INI is parsed defensively, including pathological nesting, and analyzer failures are isolated from the rest of the scan.

### Testing hygiene policy

RepoLens reports missing tests, runner configuration, and coverage setup, but it does not treat every missing optional file as a vulnerability. Absent tests are `medium`; missing runner or coverage configuration is `low`/`info`. No check inspects, installs, or runs test dependencies.

## Programmatic Usage

```python
from pathlib import Path
from repolens import ScanEngine

engine = ScanEngine()
report = engine.scan(Path("."))

print(f"Scanned {report.discovery.total_files_scanned} files in {report.duration_ms:.1f} ms")
for outcome in report.analyzer_outcomes:
    print(f"{outcome.analyzer_name:24} {outcome.status.value:12} {outcome.message or ''}")
for finding in report.findings:
    print(f"[{finding.severity.upper()}] {finding.rule_id}: {finding.title}")
```

## Running Tests & Quality Checks

```bash
pytest --cov=repolens --cov-report=term-missing
ruff check src tests
ruff format --check src tests
mypy src tests
```

The default test suite does not require network access and does not require Ruff, Bandit, or Biome to be installed: external tools are exercised through stub executables placed on a temporary `PATH`, and OSV.dev is replaced with an in-memory transport. Tests marked `network` exist only as documentation of that boundary and never call live services.

## License

Released under the [MIT License](LICENSE).
