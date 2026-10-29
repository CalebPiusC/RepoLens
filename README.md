# RepoLens
An open-source repository health checker for Python and JavaScript/TypeScript projects.

![RepoLens — See the health of your codebase.](assets/social-preview.png)

RepoLens helps developers identify, understand, and fix repository hygiene, configuration, code quality, dependency, and security issues before publishing or deploying a project.

## Current Status — Stage 3 (Command-Line Interface)

RepoLens is built in incremental stages. Stages 1, 2 and 3 are complete:

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

**Stage 3 — command-line interface**

- **`repolens` executable** (`repolens.cli`) configured through `[project.scripts]`, with `repolens --help`, `repolens --version`, and `repolens scan [PATH]`.
- **Terminal reporter** (`repolens.reporting`) showing findings by severity with rule ID, location, message, a per-analyzer status table, severity counts, and an overall result.
- **Machine-readable JSON reporter** (`repolens.json_output`) selectable with `--format json`: one deterministic document serialized from the existing `ScanReport` models, carrying a `result` verdict that always agrees with the exit code.
- **Documented exit-code policy** that distinguishes clean scans, detected findings, invalid input, operational failures, and interrupts — identical for both output formats.
- **No new dependencies:** the CLI and the JSON reporter are built on the Python standard library (`argparse`, `json`).

### Roadmap

- **Stage 1 (Complete):** Project foundation, shared analysis engine, structure analyzer, and test suite.
- **Stage 2 (Complete):** Python (`Ruff`, `Bandit`) and JavaScript/TypeScript (`Biome`) analyzer adapters, manifest/lockfile and OSV dependency checks, documentation and static test checks.
- **Stage 3 (Complete):** Command-line interface (`repolens scan`), terminal reporter, and the versioned JSON output schema (`--format json`). A Markdown reporter remains future work.
- **Stage 4:** Strict opt-in Gemini advisory explanations.
- **Stage 5:** FastAPI + HTML/HTMX web interface for GitHub archive and ZIP scanning.
- **Stage 6:** Container isolation hardening, and public beta.

## Requirements

- Python `>= 3.11`
- Linux, macOS, or Windows. Continuous integration runs the full suite and the quality gates on Ubuntu and Windows for Python 3.11, 3.12, and 3.13.

RepoLens itself has no runtime requirement on Ruff, Bandit, Biome, Node.js, or network access. External tools and OSV.dev are strictly optional.

## Installation

RepoLens requires Python `>= 3.11`.

```bash
git clone https://github.com/CalebPiusC/RepoLens.git
cd RepoLens
python3 -m venv .venv
source .venv/bin/activate

pip install .              # installs RepoLens and the `repolens` command
pip install -e ".[dev]"    # editable install with lint/test tooling
```

RepoLens is not yet published to PyPI; install it from the repository (add `.[tools]` to pull
in Ruff and Bandit). Every invocation can also be run without the console script via
`python -m repolens`.

## Command-Line Usage

```bash
$ repolens --version
repolens 0.1.0

$ repolens --help            # top-level help, commands, and exit codes
$ repolens scan --help       # scan options and examples
```

### Scanning a project

```bash
repolens scan .              # scan the current directory
repolens scan ../my-service  # scan a specific project directory
```

Example output (colors omitted):

```text
RepoLens 0.1.0 · my-service
Target: ../my-service
Scanned 412 file(s) · 3.4 MiB · in 812 ms · languages: python, typescript · 3 dirs excluded

Findings — 2 at or above 'info' severity
  SEVERITY  RULE           LOCATION            MESSAGE
  MEDIUM    RL-STRUCT-001  -                   Missing repository LICENSE file
  LOW       RL-DOC-003     README.md:12        README links to a missing path: docs/guide.md

Analyzers
  STATUS     ANALYZER                   DETAIL
  completed  repolens-structure         1 finding(s) in 4 ms
  ...        ...                        ...

Summary
  critical 0 · high 0 · medium 1 · low 1 · info 0
  total 2 finding(s)
  Result: 2 finding(s) detected at or above 'info' severity (exit code 1)
```

The per-severity counts always describe **every** finding in the report. `--min-severity`
only decides which findings gate the exit code; the `total` line and the `Result` line make
the difference explicit:

```text
Summary
  critical 0 · high 0 · medium 1 · low 0 · info 0
  total 1 finding(s) · 0 at or above 'high' severity (1 below)
  Result: no findings at or above 'high' severity (exit code 0)

Note: only findings at or above 'high' severity affect the result; the exit code ignores
lower severities, but every finding is counted in the summary above.
```

### Options

| Option | Description |
| --- | --- |
| `PATH` | Directory to scan. Defaults to `.`. Missing paths, regular files, and symlinked roots are rejected before any analyzer runs. |
| `--min-severity {info,low,medium,high,critical}` | Only findings at or above this severity affect the exit code and the `Result` line. Every finding is still listed and counted in the summary, and the `total` line reports how many are below the threshold. Default: `info`. |
| `--max-findings N` | Maximum number of findings printed in the terminal table, `1`-`10000`. Default: `50`. Truncated output is announced. It never truncates `--format json` output. |
| `--format {text,json}` | Output format. `text` (default) prints the human-readable report; `json` prints exactly one machine-readable JSON document on stdout. The exit codes and every security guarantee are identical for both. See [Machine-readable JSON output](#machine-readable-json-output). |
| `--network-checks` | Enable the optional OSV.dev known-vulnerability lookups (requires network). Disabled by default. |
| `--color {auto,always,never}` | Terminal coloring. `auto` colors only when stdout is a TTY and `NO_COLOR` is unset. Default: `auto`. |
| `--version` / `--help` | Print version or help and exit `0`. |

Use `--min-severity` to make CI gate on meaningful issues only:

```bash
repolens scan . --min-severity high   # a repository with only medium issues exits 0
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan **completed over the whole repository** and no finding met the `--min-severity` threshold. |
| `1` | At least one finding met the threshold (reported even if the scan was also incomplete). |
| `2` | Invalid arguments or unusable target path. Nothing was scanned. |
| `3` | Scan could not be completed: an analyzer failed or timed out, discovery could not read the whole repository, or an internal error occurred. |
| `130` | Scan interrupted (Ctrl-C). |

Notes on the policy:

- `1` takes precedence over `3`: detected findings are reported even when the rest of the
  scan was incomplete. The output says both ("… detected …, but the scan is incomplete").
- A scan is **incomplete** when any analyzer failed or timed out, when a directory or file
  entry could not be read (for example `EACCES`/permission denied), when discovery stopped at
  the file-count or total-byte limit, when a subtree was nested deeper than the supported
  walk depth, or when an analyzer only covered part of the repository because its file limit
  was reached. An incomplete scan never exits `0`.
- An analyzer that was **never available** (an optional tool such as Ruff, Bandit, or Biome
  is not installed) and an analyzer that was **skipped** leave the exit code untouched, so CI
  is not broken by missing optional tooling. Both are listed in the analyzer table with an
  explanatory note. Install `repolens[tools]` and Biome to close those gaps.
- A check that **started but could not complete** is different: nothing it would have covered
  was verified, so it makes the scan incomplete (exit `3`, or `1` when findings take
  precedence). This covers a requested network check failing mid-flight and a tool
  disappearing between the availability probe and the run:
  `Warning: 1 check(s) started but could not complete, so results are incomplete: …`
- Large or deeply nested repositories that hit a resource limit can raise it through the
  programmatic API (`ScanConfig(max_files=…, max_total_bytes=…, max_tool_files=…)`); the CLI
  uses the defaults (10 000 files, 50 MiB in total, 2 000 files per external tool).
- Exit codes `2` and `3` both mean "no trustworthy clean result": `2` means nothing was
  scanned at all, `3` means scanning started but the coverage is incomplete.

#### Partial scans and false-clean protection

Coverage gaps that could hide a finding are surfaced as warnings in the output and all make
the scan incomplete (exit `3` unless a finding at or above the threshold takes precedence
with exit `1`):

| Situation | Reported as | Exit code |
| --- | --- | --- |
| Directory could not be opened (`os.scandir` raised `OSError`) | `Warning: could not read N directories, …` | `3` (or `1` with findings) |
| Entry could not be inspected (stat/resolve failed) | `Warning: could not read … N entries, …` | `3` (or `1` with findings) |
| File-count or byte limit reached | `Warning: discovery stopped early after reaching the … limit` | `3` (or `1` with findings) |
| Subtree deeper than `MAX_DIRECTORY_DEPTH` (64 levels) | `Warning: discovery skipped N directories nested deeper than the supported limit of 64 levels, …` | `3` (or `1` with findings) |
| Analyzer hit `max_tool_files`, so it linted only some files | `Warning: N analyzer(s) covered only part of the repository because a file limit was reached …` | `3` (or `1` with findings) |

Deliberate policy skips are **disclosed but do not change the exit code**, because removing
them would make ordinary repositories look broken:

| Situation | Why it stays non-blocking | Disclosed as |
| --- | --- | --- |
| Excluded directories (`.git`, `node_modules`, `.venv`, `dist`, `build`, `out`, `target`, `coverage`, …) | Conventional VCS/vendor/build output that is not project source; the list is fixed and never read from the scanned repository's configuration | `· N dirs excluded` on the `Scanned …` line |
| Symbolic links | Security boundary: RepoLens never follows symlinks out of the repository | `Note: N symbolic link(s) were not followed.` |
| Files above `max_file_size_bytes` | Per-file resource cap prevents unbounded reads | `Note: N file(s) exceeded the per-file size limit and were not analyzed.` |

A file that is neither a regular file nor a directory (socket, FIFO, device) is skipped
without a counter; such entries can never contain analyzable source, so this cannot hide a
finding. Directories skipped by the depth limit are the only "nested" case that can hide real
source, which is why they make the scan incomplete.

Typical CI usage:

```bash
pip install ".[tools]"          # or: pip install ruff bandit
repolens scan . --min-severity medium
```

The command's own exit status is the CI result: `0` clean, `1` findings, `2`/`3`/`130` are
errors that must fail the build as well.

### Error handling

Invalid paths and operational failures are printed to **stderr** as single-line messages
without stack traces, for example:

```text
$ repolens scan /does/not/exist
repolens: error: Repository path does not exist: /does/not/exist
$ echo $?
2
```

A security abort that happens *after* discovery started is not reported as a usage error
(nothing was scanned); it exits `3` with `repolens: error: scan aborted part-way: …`, because
part of the repository was already scanned.

Unexpected internal errors are reported with the exception type and a scrubbed message plus a
link to the issue tracker; secrets are redacted before anything is printed.

`Ctrl-C` returns `130` whether it arrives during discovery, during an analyzer, or while the
report is being rendered and printed — no traceback is shown in any of those cases.

## Machine-readable JSON output

`--format json` writes exactly one JSON document to stdout and nothing else, so it can be piped
straight into `jq`, uploaded as a CI artifact, or consumed by another program:

```bash
repolens scan . --format json > repolens-report.json
repolens scan . --format json | jq '.result.status, .result.exit_code'
repolens scan . --format json | jq -r '.findings[] | "\(.severity)\t\(.rule_id)\t\(.location.path)"'
```

The exit code is unchanged by the format: `0` clean, `1` findings, `2` usage, `3` incomplete,
`130` interrupt. A JSON document is only written when the scan produced a report; usage and
operational errors still print a single-line diagnostic to **stderr** and leave stdout empty, so
`json.load(sys.stdin)` never sees a half-written document.

### Document shape

```json
{
  "schema_version": "1.1.0",
  "repolens_version": "0.1.0",
  "repository_name": "my-service",
  "scanned_at": "2026-10-29T09:40:11.768464Z",
  "duration_ms": 812.4,
  "discovery": {
    "total_files_scanned": 412,
    "total_bytes_scanned": 3565158,
    "skipped_excluded_count": 3,
    "skipped_symlink_count": 0,
    "skipped_oversized_count": 0,
    "sensitive_files_detected": 0,
    "truncated_by_file_limit": false,
    "truncated_by_byte_limit": false,
    "unreadable_directory_count": 0,
    "unreadable_entry_count": 0,
    "skipped_by_depth_count": 0,
    "detected_languages": ["python", "typescript"]
  },
  "analyzer_outcomes": [
    {
      "analyzer_name": "ruff-python-lint",
      "status": "completed",
      "findings_count": 1,
      "duration_ms": 36.2,
      "message": "Ruff analyzed 128 Python file(s).",
      "coverage_truncated": false,
      "coverage_incomplete": false
    },
    {
      "analyzer_name": "biome-jsts-lint",
      "status": "unavailable",
      "findings_count": 0,
      "duration_ms": 0.0,
      "message": "`biome` executable was not found on PATH (optional tool not installed).",
      "coverage_truncated": false,
      "coverage_incomplete": false
    }
  ],
  "findings": [
    {
      "rule_id": "RL-DOC-003",
      "category": "documentation",
      "severity": "low",
      "confidence": "medium",
      "title": "README links to a missing path: docs/guide.md",
      "location": {"path": "README.md", "start_line": 3, "end_line": null, "column": null},
      "evidence": "Markdown link target `docs/guide.md` does not exist.",
      "explanation": "Broken relative documentation links confuse contributors and are often a sign that files were moved or deleted without updating docs.",
      "recommendation": "Fix the link target or restore `docs/guide.md`.",
      "verification": "Open the rendered README and confirm the link resolves.",
      "source": {
        "kind": "deterministic",
        "tool": "repolens-documentation",
        "tool_version": "0.1.0",
        "rule_url": null
      },
      "fingerprint": "dd56d3342caaf8c2a3f0c15a"
    }
  ],
  "ai_advisories": [],
  "result": {
    "exit_code": 1,
    "min_severity": "info",
    "status": "findings",
    "has_findings": true,
    "is_complete": true,
    "incomplete_reasons": [],
    "findings_total": 1,
    "findings_at_or_above_threshold": 1,
    "counts_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0},
    "counts_by_category": {
      "code_quality": 0,
      "security": 0,
      "dependencies": 0,
      "documentation": 1,
      "testing": 0,
      "structure": 0
    }
  }
}
```

The document body is `ScanReport.model_dump(mode="json")` — the same Pydantic models the
library returns. There is no parallel reporting schema to drift out of sync. `result` is the
only added member; it is derived from the same verdict that decides the exit code, so a
consumer never has to re-implement that policy.

**Upgrading from the `1.0.0` report.** The addition of `result` is additive, but a *strict*
reader is affected: `ScanReport` sets `extra="forbid"`, so validating the new CLI document with
an old `ScanReport` model fails with `Extra inputs are not permitted` for the `result` member.
That is expected, not damage — the report body itself is unchanged. Three ways to handle it:

```python
import json
from repolens.json_output import parse_json_document

payload = json.loads(text)

# 1. Use the maintained parser (validates the body and result separately).
parsed = parse_json_document(text)

# 2. Keep your own model, but hand it only the body.
from repolens.models import ScanReport
report = ScanReport.model_validate({k: v for k, v in payload.items() if k != "result"})

# 3. Or read leniently and let the parser ignore members it does not know.
parsed = parse_json_document(text, strict=False)
```

Any existing field keeps its name, type, and meaning, so a reader that ignores unknown members —
or that validates the body alone — continues to work unchanged.

### `result` semantics

| Member | Meaning |
| --- | --- |
| `exit_code` | The process exit code, identical to what the shell observes. |
| `min_severity` | The `--min-severity` threshold applied to findings for the verdict. |
| `status` | `clean`, `findings`, `incomplete`, or `findings_and_incomplete`. |
| `has_findings` | At least one finding met the threshold. |
| `is_complete` | Everything RepoLens set out to check was actually verified. |
| `incomplete_reasons` | Sorted, de-duplicated reasons: `analyzer_failed`, `analyzer_timed_out`, `analyzer_coverage_truncated`, `check_aborted`, `discovery_unreadable`, `discovery_truncated`, `discovery_depth_limited`. |
| `findings_total` / `findings_at_or_above_threshold` | Every finding, versus the ones that gated the exit code. |
| `counts_by_severity` / `counts_by_category` | Counts for **every** enum member including zeros, in enum order, so a key can be read unconditionally. |

### How to tell whether a scan is complete

Read `result.is_complete` (and `result.incomplete_reasons` for why) rather than interpreting
analyzer statuses yourself: that single boolean is what the exit code is derived from.

Five analyzer situations look similar in the analyzer table but differ in effect:

| Situation | `analyzer_outcomes[]` | Scan incomplete? | Exit code |
| --- | --- | --- | --- |
| Optional tool never installed — the check never started | `status: "unavailable"`, `coverage_incomplete: false` | No | Unchanged |
| Analyzer not applicable to this repository, or deliberately skipped | `status: "skipped"` | No | Unchanged |
| Analyzer ran but covered only part of the files (a tool file cap was reached) | `status: "completed"`, `coverage_truncated: true` | Yes — `analyzer_coverage_truncated` | `3` (or `1` with findings) |
| Analyzer started and then failed or timed out | `status: "failed"` / `"timed_out"`, `coverage_incomplete: false` | Yes — `analyzer_failed` / `analyzer_timed_out` | `3` (or `1` with findings) |
| Check started, then could not complete (for example a requested network lookup failed mid-flight) | `status: "unavailable"` **with** `coverage_incomplete: true` | Yes — `check_aborted` | `3` (or `1` with findings) |

Note that `coverage_incomplete` is **not** the general "this scan is incomplete" flag: it marks
only the *started-then-aborted* case, where a check reported a status that would otherwise look
like a benign "not installed". A failed or timed-out analyzer makes the scan incomplete through
its status and the matching `incomplete_reasons` entry, even though `coverage_incomplete` is
`false` for it. Consumers that only inspect `coverage_incomplete` will miss those scans, so key
off `result.is_complete` (or `result.incomplete_reasons`) instead.

### Guarantees

- **Nothing but the document on stdout.** No banner, progress text, ANSI color (even with
  `--color always`), or human-readable summary is mixed into the stream. Diagnostics stay on
  stderr.
- **Complete findings.** `--max-findings` limits only the terminal table; the JSON document
  always contains every finding.
- **Deterministic.** For the same repository content and options, the document is byte-identical
  except for `scanned_at` and the `duration_ms` values. Member order is fixed (report fields in
  model order, then `result`), findings keep the engine's deterministic sort (severity rank,
  category, path, line, rule ID, fingerprint), analyzer outcomes keep analyzer order, and count
  maps are emitted in enum order.
- **Portable encoding.** Output is ASCII-only (`\uXXXX` escapes for non-ASCII names) so the bytes
  are identical regardless of the console encoding, including Windows code pages. Timestamps are
  RFC 3339 in UTC with a `Z` suffix; paths are repository-relative POSIX paths with forward
  slashes; optional values are `null`, never omitted; enums are their documented string values.
- **Same security model.** The document is serialized from already-redacted report models, so
  secret redaction, sensitive-file blocking, and symlink rules apply exactly as they do for
  terminal output.

### Schema versioning

`schema_version` identifies the **shape** of the document, independently of `repolens_version`
(which identifies the package release). It follows semantic versioning:

| Change | Version bump |
| --- | --- |
| Removing or renaming a member, changing a type or the meaning of a value, adding a required member | **MAJOR** |
| Adding a member, a new optional member, or a new enum value | **MINOR** |
| Documentation or clarification only, no shape change | **PATCH** |

**Consumers must handle two different kinds of change differently:**

| Change | Reader requirement |
| --- | --- |
| **Unknown member** (a field the reader does not know) | Ignore it. Additive members never change the meaning of members that already exist. |
| **Unknown value** for a *known* member (for example a new `result.status` or `incomplete_reasons[]` entry) | Do **not** guess. Treat the scan as *indeterminate* and re-scan with a newer RepoLens, rather than mapping the value onto a neighbouring known one. |

Guessing a value is the dangerous direction: coercing an unrecognized `status` or dropping an
unrecognized `incomplete_reasons[]` entry could turn an incomplete scan into a clean one.

#### Version acceptance policy

`repolens.json_output.parse_json_document` applies this policy explicitly
(`repolens.models.SUPPORTED_SCHEMA_MAJOR_VERSIONS`):

| Document version | Result |
| --- | --- |
| Same **major** as the parser — any minor/patch, newer *or* older (for example `1.0.0`, `1.1.0`, `1.7.3`) | Accepted. Additive MINOR changes are handled per the table above. |
| Different **major** — a newer one (`2.0.0`, `3.4.5`) or a pre-1.0 one (`0.9.0`) | Rejected with `repolens.exceptions.UnsupportedSchemaVersionError`, naming both the document version and the version this RepoLens reads. |
| Missing, non-string, or not `MAJOR.MINOR.PATCH` | Rejected with `repolens.exceptions.ScanDocumentError`. |

The version is checked **before** the rest of the document, so a future document reports "I do
not understand this version" instead of a confusing field-level error. Both exceptions subclass
`ValueError` (and `ScanDocumentError` subclasses `RepoLensError`), so existing `except ValueError`
blocks keep working while callers can catch the specific type.

#### Strict and forward-compatible parsing

`parse_json_document` offers both readings of the policy:

| Mode | Unknown members | Unknown values |
| --- | --- | --- |
| `strict=True` (default) | `ValidationError` | `ValidationError` |
| `strict=False` | Ignored anywhere in the document (root, `result`, `findings[]`, `analyzer_outcomes[]`, `discovery`, …) | `UnsupportedSchemaValueError` |

```python
from repolens.exceptions import (
    ScanDocumentError,
    UnsupportedSchemaValueError,
    UnsupportedSchemaVersionError,
)
from repolens.json_output import parse_json_document

try:
    parsed = parse_json_document(text, strict=False)  # tolerate additive MINOR changes
except UnsupportedSchemaVersionError:
    ...   # written by a different MAJOR schema: upgrade RepoLens / regenerate the report
except UnsupportedSchemaValueError:
    ...   # a value this version cannot interpret: treat the scan as indeterminate
except ScanDocumentError:
    ...   # not a RepoLens scan document at all
```

Limitation of `strict=False`: it only tolerates unknown **members**. An unknown value for a
known member still stops parsing, by design — that is what keeps an unrecognized status or
reason from silently producing a wrong clean/incomplete verdict. Missing *required* members are
still errors in both modes; tolerating additions must not become tolerating omissions.

**Current version: `1.1.0`.** It was bumped from `1.0.0` in this milestone, intentionally:

- The report fields themselves did not change name, type, or meaning, so this is an *additive*
  change.
- The CLI now guarantees a `result` member and documents determinism, ordering, and encoding
  rules that did not exist before, which is a real contract change for consumers.
- Semver calls an additive change a **MINOR** bump, hence `1.1.0` rather than `2.0.0`.

The version is defined once, as `repolens.models.SCHEMA_VERSION`, with
`SCHEMA_MAJOR_VERSION` and `SUPPORTED_SCHEMA_MAJOR_VERSIONS` derived from it, and it is validated
against the `MAJOR.MINOR.PATCH` shape so an accidental malformed value fails fast instead of
reaching a consumer.

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
- Reports service problems explicitly instead of guessing: timeouts produce a `timed_out` outcome, connection/HTTP errors produce `unavailable` marked as coverage-incomplete, and unreadable payloads produce `failed`.
- An OSV.dev failure after the lookup started is never described as a missing optional tool: because `--network-checks` was requested explicitly, the scan exits `3` instead of reporting clean.
- Never labels a dependency vulnerable without an advisory ID returned by OSV.dev. When OSV publishes no severity, the finding is marked medium severity with low confidence, and the explanation says the rating is estimated.

Disabling network checks (default) still runs every offline check. Outcome messages state why the OSV analyzer was skipped.

## Security model

RepoLens is a static-analysis tool:

- It never executes code from the target repository (no `setup.py`, no npm scripts, no test suites, no build steps).
- It never installs packages from the target repository or resolves its dependencies.
- Subprocesses are invoked with structured argument lists (`shell=False`), a sanitized environment (host secrets removed), a disposable working directory outside the repository, and both time and output-size limits. On timeout the whole process tree is terminated: a POSIX session group on Linux/macOS, and a Windows process group plus `taskkill /T` on Windows, so a wrapper (`cmd.exe` around a `.cmd` shim) cannot leave the real analyzer running.
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

The CLI is a thin front end over exactly this API: `repolens.cli` builds a `ScanConfig`,
calls `ScanEngine.scan()`, and renders the resulting `ScanReport` with
`repolens.reporting.render_report()`. To render a report you already have:

```python
from repolens.json_output import render_json
from repolens.reporting import RenderOptions, render_report

print(render_report(report, options=RenderOptions(color=False)))

# The same JSON document the CLI emits with --format json.
print(render_json(report, exit_code=0))
```

A document written by the CLI can be read back into validated models — the report body and the
`result` verdict are validated separately, because `ScanReport` forbids unknown members by design:

```python
from repolens.json_output import parse_json_document

text = Path("repolens-report.json").read_text(encoding="utf-8")
parsed = parse_json_document(text)  # exact validation; add strict=False to tolerate additions
print(parsed.report.findings[0].rule_id, parsed.result.status)
```

The parser checks `schema_version` first and refuses a document from a different major schema
version. See [Schema versioning](#schema-versioning) for the acceptance policy and for what
`strict=False` does and does not tolerate.

## Running Tests & Quality Checks

```bash
pytest --cov=repolens --cov-report=term-missing
ruff check src tests
ruff format --check src tests
mypy src tests
```

The suite includes CLI tests that drive `main()` with a fake engine and packaging tests that
invoke the installed entry point in a subprocess.

The default test suite does not require network access and does not require Ruff, Bandit, or Biome to be installed: external tools are exercised through stub executables placed on a temporary `PATH`, and OSV.dev is replaced with an in-memory transport. Tests marked `network` exist only as documentation of that boundary and never call live services.

Stub tools are generated as Python scripts behind a native launcher (a `.cmd` shim on Windows, a shell wrapper elsewhere), so the same tests exercise the real subprocess path on every platform.

Two Windows environment capabilities are handled by skipping, never by weakening assertions:

- Symbolic-link tests are skipped when the host cannot create symlinks. Unprivileged Windows accounts may only create them with Developer Mode enabled; the Windows CI runner can, so the boundary stays covered there.
- Tests for the 64-level `<MAX_DIRECTORY_DEPTH>` limit nest single-character directories under a short scratch root, and skip if the filesystem still refuses. Windows enforces a ~260 character path limit unless long paths are enabled, which a deep tree below pytest's own temporary directory would exceed.

Directory-permission tests are skipped on platforms that do not enforce `chmod` (Windows).

## License

Released under the [MIT License](LICENSE).
