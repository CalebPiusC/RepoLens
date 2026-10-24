# RepoLens
An open-source repository health checker for Python and JavaScript/TypeScript projects.

![RepoLens — See the health of your codebase.](assets/social-preview.png)

RepoLens helps developers identify, understand, and fix repository hygiene, configuration, code quality, dependency, and security issues before publishing or deploying a project.

## Current Status — Stage 1 (Foundation & Shared Engine)

RepoLens is built in incremental stages. Stage 1 provides the core shared analysis engine and security boundaries:

- **Validated report schema (`repolens.models`):** Strict Pydantic v2 models (`Finding`, `AIAdvisory`, `AnalyzerOutcome`, `ScanReport`) with structural separation between deterministic scanner findings and future opt-in AI advisories.
- **Safe repository discovery (`repolens.discovery`):** Canonical root enforcement, symlink escape rejection, TOCTOU `O_NOFOLLOW` file reads, sensitive-file read blocks (`.env*`, private keys, credential files), `.gitignore` evaluation, and file/byte resource caps.
- **Evidence secret redaction (`repolens.redaction`):** Automatic scrubbing of API keys, tokens, private keys, JWTs, and credential URLs before evidence or error messages enter a report.
- **Hardened subprocess runner (`repolens.subprocess_runner`):** `shell=False` execution, allowlist-only environment sanitization, output byte caps, and process-group timeouts for external static analyzers.
- **Shared scan engine & structure analyzer (`repolens.engine`, `repolens.analyzers.structure`):** Deterministic checks for `LICENSE`, `README`, `.gitignore` ecosystem coverage, unignored sensitive files, unignored vendor/virtualenv directories, `pyproject.toml` / `package.json` validity, JS/TS lockfile hygiene, and committed binary/archive bloat.

### Roadmap

- **Stage 1 (Complete):** Project foundation, shared analysis engine, structure analyzer, and test suite.
- **Stage 2 (Next):** Python (`Ruff`, `Bandit`) and JavaScript/TypeScript (`Biome`) analyzer adapters, lockfile/OSV dependency checks, documentation & static test checks.
- **Stage 3:** Command-line interface (`repolens scan`) and Terminal, JSON, and Markdown reporters.
- **Stage 4:** Strict opt-in Gemini advisory explanations.
- **Stage 5:** FastAPI + HTML/HTMX web interface for GitHub archive and ZIP scanning.
- **Stage 6:** Container isolation hardening, CI workflows, and public beta.

## Requirements

- Python `>= 3.11`

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Programmatic Usage

```python
from pathlib import Path
from repolens import ScanEngine

engine = ScanEngine()
report = engine.scan(Path("."))

print(f"Scanned {report.discovery.total_files_scanned} files in {report.duration_ms:.1f} ms")
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

## License

Released under the [MIT License](LICENSE).
