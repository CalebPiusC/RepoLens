# Architecture

## Overview

RepoLens is a static repository health checker that operates entirely without executing or installing anything from the target repository. It accepts a filesystem path, discovers every relevant file within configurable resource limits, runs a sequence of independent analyzers against the discovered content, and returns a structured report of findings. The design emphasises three properties above all others: **safety** (no code from the target repository is ever trusted or executed), **determinism** (findings are reproducible and fingerprinted), and **fault isolation** (a failure in any single analyzer never aborts the rest of the scan).

---

## Scan Pipeline

The following diagram shows the complete execution path from CLI invocation to final report output.

```mermaid
flowchart TD
    A["CLI (cli.py)\nargparse, exit codes"] --> B["ScanEngine (engine.py)\norchestrates scan"]
    B --> C["discover_repository()\ndiscovery.py"]
    C --> D["DiscoverySummary\nfile list, byte counts, languages"]
    D --> B
    B --> E["Analyzer 1\nstructure.py"]
    B --> F["Analyzer 2\npython_lint.py"]
    B --> G["Analyzer 3\njsts_lint.py"]
    B --> H["Analyzer 4\ndependencies.py"]
    B --> I["Analyzer 5\ndocumentation.py"]
    B --> J["Analyzer 6\ntesting.py"]
    B --> K["Analyzer 7\nadvisories.py"]
    E & F & G & H & I & J & K --> L["findings: list[Finding]"]
    L --> M["ScanReport (models.py)\nimmutable, schema-versioned"]
    M --> N["Reporting (reporting.py)\nterminal render, verdict"]
    N --> O["Exit code\n0 / 1 / 2 / 3 / 130"]
```

Each analyzer box runs inside a try/except block inside `ScanEngine`. An exception in any box records a `failed` outcome for that analyzer and continues to the next.

---

## Module Relationships

```mermaid
classDiagram
    class ScanEngine {
        +config: ScanConfig
        +analyzers: list[Analyzer]
        +scan(path) ScanReport
    }
    class ScanConfig {
        +max_files: int
        +max_file_size_bytes: int
        +max_total_bytes: int
        +subprocess_timeout_seconds: int
        +enable_network_checks: bool
        +excluded_dirs: set[str]
    }
    class BaseAnalyzer {
        <<abstract>>
        +is_applicable(summary) bool
        +check_availability() bool
        +skip_reason() str
        +analyze(path, files, config) AnalyzerOutcome
        +coverage_partial() bool
        +completion_message() str
    }
    class ScanReport {
        +schema_version: str
        +repolens_version: str
        +findings: list[Finding]
        +analyzer_outcomes: dict
        +discovery: DiscoverySummary
    }
    class Finding {
        +rule_id: str
        +category: str
        +severity: str
        +confidence: str
        +location: str
        +evidence: str
        +fingerprint: str
    }
    class DiscoverySummary {
        +total_files: int
        +total_bytes: int
        +detected_languages: list[str]
        +truncated: bool
        +incomplete: bool
    }
    class Reporter {
        +options: RenderOptions
        +evaluate(report) str
        +render_report(report) str
    }
    class SubprocessRunner {
        +run(cmd, cwd, env) CompletedProcess
    }
    class Redaction {
        +scrub(text) str
    }

    ScanEngine --> ScanConfig : configured by
    ScanEngine --> BaseAnalyzer : runs each
    ScanEngine --> ScanReport : produces
    ScanReport --> Finding : contains
    ScanReport --> DiscoverySummary : contains
    BaseAnalyzer --> SubprocessRunner : uses
    BaseAnalyzer --> Redaction : uses
    Reporter --> ScanReport : renders
```

---

## Module Overview

### `engine.py` — ScanEngine

`ScanEngine` is the central orchestrator. It accepts a `ScanConfig` and a list of `Analyzer` instances at construction time. When `scan(path)` is called it:

1. Calls `discover_repository(path, config)` to produce a `DiscoverySummary` and the list of discovered file paths.
2. Iterates through each analyzer. For each: checks `is_applicable()`, checks `check_availability()`, then calls `analyze()`.
3. Collects all `Finding` objects and `AnalyzerOutcome` records.
4. Assembles and returns an immutable `ScanReport`.

All analyzer calls are wrapped in fault-isolation blocks. A raised exception records the analyzer as `failed` without interrupting the remaining analyzers.

---

### `discovery.py` — Repository Discovery

Discovery performs a safe iterative depth-first walk of the target directory. Key guarantees:

- Symlinks are never followed. Any symlink encountered is recorded and excluded.
- All file reads are opened with `O_NOFOLLOW` to prevent time-of-check/time-of-use (TOCTOU) race conditions.
- Sensitive filenames (`.env`, SSH private keys, PEM files, credential stores) are detected and excluded from content reads; their presence is recorded in the summary.
- Per-file size is capped at `max_file_size_bytes` (1 MiB by default). Total bytes across all files is capped at `max_total_bytes` (50 MiB).
- Directory traversal depth is capped at 64 levels.
- `.gitignore` rules are evaluated to respect project-defined exclusions.
- Directories listed in `excluded_dirs` (`node_modules`, `.venv`, `dist`, `.git`, etc.) are never entered.
- Any directory or entry that cannot be read is recorded as a scan-incomplete condition; the report is never marked clean when content was inaccessible.

---

### `models.py` — Data Models

All data models are Pydantic v2 models with full validation.

**`Finding`**: The unit of output from all deterministic analyzers. Each field is described below.

| Field | Type | Notes |
|---|---|---|
| `rule_id` | `str` | Stable identifier such as `RL-STRUCT-001` or `RUFF-E501`. |
| `category` | `str` | One of: `structure`, `security`, `dependencies`, `documentation`, `testing`, `code_quality`. |
| `severity` | `str` | One of: `critical`, `high`, `medium`, `low`, `info`. |
| `confidence` | `str` | Analyzer-assigned confidence level. |
| `location` | `str` | File path and optional line number. |
| `evidence` | `str` | Auto-redacted before storage. |
| `explanation` | `str` | Human-readable description. |
| `recommendation` | `str` | Actionable remediation step. |
| `source` | `str` | Always `deterministic` for `Finding`. |
| `fingerprint` | `str` | SHA-256 hash auto-generated from stable fields. |

**`AIAdvisory`**: Structurally separate from `Finding`. Intended for future opt-in Gemini-powered explanations. Never mixed into the deterministic findings list.

**`AnalyzerOutcome`**: Records the result of each analyzer run. Status values: `completed`, `skipped`, `unavailable`, `timed_out`, `failed`. Also records `duration_ms` and flags for truncated or incomplete coverage.

**`ScanReport`**: The top-level output model. Fields include `schema_version`, `repolens_version`, `repository_name`, `scanned_at`, `duration_ms`, the `DiscoverySummary`, a dict of `AnalyzerOutcome` records keyed by analyzer name, the list of `Finding` objects, and an optional list of `AIAdvisory` objects.

---

### `analyzers/` — Analyzer Modules

Each analyzer extends `BaseAnalyzer` (defined in `analyzers/base.py`). The engine calls the following interface in order:

1. `is_applicable(summary)`: Returns `False` if the analyzer has nothing to work on (for example, the JS/TS linter returns `False` for Python-only repos).
2. `check_availability()`: Returns `False` if a required external tool is not installed.
3. `analyze(path, files, config)`: Performs the analysis and returns an `AnalyzerOutcome` alongside any findings.

The analyzers are:

| Module | Rule Prefix | Description |
|---|---|---|
| `structure.py` | `RL-STRUCT` | Repository structure and hygiene checks. |
| `python_lint.py` | `RUFF-`, `BANDIT-` | Runs Ruff and Bandit against Python files. |
| `jsts_lint.py` | `BIOME-` | Runs Biome against JavaScript and TypeScript files. |
| `dependencies.py` | `RL-DEP` | Parses manifests and lockfiles for dependency issues. |
| `documentation.py` | `RL-DOC` | Cross-references README, LICENSE, and manifest metadata. |
| `testing.py` | `RL-TEST` | Checks for test presence, runner config, and coverage setup. |
| `advisories.py` | `OSV-` | Queries OSV.dev for known vulnerabilities (opt-in). |

---

### `cli.py` — Command-Line Interface

A thin `argparse` wrapper. The single command is `repolens scan [PATH]`. When `PATH` is omitted, the current working directory is used. Options include `--min-severity`, `--max-findings`, `--color`, `--network-checks`, and `--version`. Exit codes are:

| Code | Meaning |
|---|---|
| 0 | Scan completed with no findings at or above `--min-severity`. |
| 1 | Scan completed and findings were produced. |
| 2 | Usage error (bad arguments). |
| 3 | Operational error or incomplete scan. |
| 130 | Interrupted by the user (SIGINT). |

---

### `reporting.py` — Terminal Reporter

`Reporter` accepts a `RenderOptions` struct (`color`, `min_severity`, `max_findings`). `evaluate()` derives the exit verdict from the report. `render_report()` produces the formatted terminal string. Findings are filtered by `min_severity` and capped at `max_findings` before rendering.

---

### `redaction.py` — Secret Redaction

Before any evidence string or error message is stored in a `Finding` or logged, it is passed through the redaction module. The redaction module applies regular expression patterns to detect and replace:

- API keys and bearer tokens
- Private key PEM blocks
- JSON Web Tokens
- Credential-bearing URLs (e.g., `https://user:password@host/`)
- Common environment variable assignment patterns for secrets

Redaction is applied at the point of data entry into models, not at render time, ensuring that sensitive content never appears in any serialised form of the report.

---

### `subprocess_runner.py` — Subprocess Execution

All external tool invocations (Ruff, Bandit, Biome) go through `SubprocessRunner`. Guarantees:

- `shell=False` on every call. Command arguments are passed as a list, never interpolated into a shell string.
- The child process receives only an allowlisted set of environment variables. `PATH` is included; arbitrary inherited environment variables are not.
- Output is capped at `subprocess_max_output_bytes` (5 MiB). Output beyond the cap is discarded.
- On POSIX systems (Linux, macOS), the child is started in a new process group and the entire group is killed on timeout. On Windows, a Job Object achieves equivalent group termination.
- The timeout is `subprocess_timeout_seconds` (30 s by default).

---

## Data Flow

```mermaid
flowchart LR
    subgraph Input
        A["Filesystem path"]
        B["ScanConfig"]
    end
    subgraph Discovery
        C["DFS walk\nO_NOFOLLOW\nsymlink rejection\nbyte caps"]
        D["DiscoverySummary\n+ file list"]
    end
    subgraph Analysis
        E["Analyzers\n(sequential, fault-isolated)"]
        F["SubprocessRunner\n(shell=False, env allowlist)"]
        G["OSV.dev API\n(opt-in, HTTPS only)"]
    end
    subgraph Output
        H["Redaction"]
        I["ScanReport\n(immutable)"]
        J["Terminal render\n+ exit code"]
    end

    A --> C
    B --> C
    C --> D
    D --> E
    E --> F
    E --> G
    E --> H
    H --> I
    I --> J
```

---

## Security Boundaries

RepoLens applies a strict boundary between itself and the repository it scans. Nothing from the target repository is executed. The boundaries are:

**Filesystem boundary**: Discovery reads files but never `exec`s them, never imports them as Python modules, never evaluates them, and never dereferences symlinks. File reads are performed with `O_NOFOLLOW`.

**Process boundary**: When external linting tools are invoked, they are given the target files as arguments but run inside a disposable working directory with a sanitised environment. They cannot reach back into the RepoLens process.

**Network boundary**: Network access is disabled by default. When `--network-checks` is enabled, only HTTPS requests to `api.osv.dev` are permitted. HTTP redirects are rejected. Request payloads contain only package name, version, and ecosystem: no file content and no repository metadata.

**Output boundary**: All findings pass through the redaction layer before they are stored. Sensitive content cannot leak from the analysis phase into the report.

---

## Resource Limits

| Limit | Default |
|---|---|
| Maximum files discovered | 10,000 |
| Maximum size per file | 1 MiB |
| Maximum total bytes read | 50 MiB |
| Maximum directory depth | 64 |
| Subprocess timeout | 30 s |
| Subprocess max output | 5 MiB |
| Maximum tool-visible files | 2,000 |

All limits are defined in `ScanConfig` and can be adjusted when constructing `ScanEngine` programmatically.

---

## Extension Points

**Adding an analyzer**: Subclass `BaseAnalyzer`, implement the required interface, and pass an instance to `ScanEngine`. No registration mechanism is needed; the engine accepts any list of analyzers.

**Custom config**: Construct `ScanConfig` with non-default values before passing it to `ScanEngine`. All limits and toggles are exposed as typed Pydantic fields.

**Programmatic use**: `ScanEngine`, `ScanConfig`, and all models are importable from `repolens`. The CLI is a thin consumer of the same API that any Python script can use.

**AI advisories (Stage 4)**: The `AIAdvisory` model and the separation between deterministic findings and advisory explanations are already in place. The Gemini integration layer will populate `AIAdvisory` objects without altering the `Finding` list or fingerprints.
