# Rules Reference

Every rule ID RepoLens can emit, grouped by analyzer, with its category and severity. Severities
from highest to lowest: `critical`, `high`, `medium`, `low`, `info`. This reference is derived
from the analyzer sources in `src/repolens/analyzers/` — if the two ever disagree, the code (and
its tests) wins; please open an issue.

Rule IDs are stable identifiers. There is currently no per-rule suppression or filtering option;
`--min-severity` is the only threshold control.

## Severity thresholds and output formats

`--min-severity` (default `info`) decides which findings gate the exit code and the verdict:

- **Text (`--format text`):** only findings at or above the threshold appear as table rows
  (further capped by `--max-findings`, default 50); the summary always counts **every** finding
  and states how many are below the threshold.
- **JSON (`--format json`):** the `findings` array always contains every finding, regardless of
  threshold or `--max-findings`. Use `result.min_severity`,
  `result.findings_at_or_above_threshold`, `result.status`, and `result.is_complete` instead of
  re-deriving the verdict. See "Machine-readable JSON output" in the root README.
- **Exit code:** `1` if any finding meets the threshold (even if the scan is also incomplete);
  otherwise `3` if the scan is incomplete; otherwise `0`. Usage errors exit `2` and interrupts
  exit `130`. An incomplete scan never exits `0`.

## Finding fingerprints

Each `Finding.fingerprint` is the first 24 hex characters of a SHA-256 digest over:

```text
source.tool | rule_id | category | location-key | title
```

where the location key is `path:start_line:end_line` (missing lines as `0`), or `<repo>` when the
finding has no location. Evidence, explanation, severity, scan timestamp, and duration do **not**
contribute. The engine deduplicates findings by fingerprint and sorts them by severity rank,
category, path, line, rule ID, and fingerprint, so the same repository content yields the same
finding set and order. A caller-supplied non-empty fingerprint is preserved as-is.

## Structure and sensitive files (`repolens-structure`)

Source: `src/repolens/analyzers/structure.py`.

| Rule ID | Category | Severity | Trigger |
| --- | --- | --- | --- |
| `RL-STRUCT-001` | structure | medium | No root `LICENSE`/`COPYING` file. |
| `RL-STRUCT-002` | documentation | medium | No root `README.md`/`.rst`/`.txt`, or the root README is empty. |
| `RL-STRUCT-003` | structure | medium | No root `.gitignore`. |
| `RL-STRUCT-004` | structure | low | Python detected but root `.gitignore` does not cover `__pycache__`/`*.pyc`, `.venv`/`venv`, or `.env` (one finding listing what is missing). |
| `RL-STRUCT-005` | structure | medium | JavaScript/TypeScript detected but `node_modules/` is not ignored. |
| `RL-STRUCT-006` | structure | medium | A generated/vendor directory (`node_modules`, `.venv`, `venv`, `__pycache__`) is present in the workspace and not ignored (one finding per directory). |
| `RL-STRUCT-007` | structure | medium | Python sources without `pyproject.toml`/`requirements.txt`, or JS/TS sources without `package.json`. |
| `RL-STRUCT-008` | structure | low | Root `package.json` declares dependencies but no JS lockfile is present. |
| `RL-STRUCT-009` | structure | low | Multiple conflicting JS lockfiles at the root (different package managers). |
| `RL-STRUCT-010` | structure | low | A file is oversized (over `max_file_size_bytes`) or has a binary/archive extension (`.zip`, `.whl`, `.so`, `.dll`, `.exe`, `.jar`, `.sqlite`, `.db`, and similar) and is not ignored. Ordinary images are only flagged when oversized. |
| `RL-STRUCT-011` | structure | high | Root `pyproject.toml` is not valid TOML, or root `package.json` is not valid/safely parseable JSON. |
| `RL-STRUCT-012` | structure | low | Root `.gitignore` ignores lockfiles or `tests`/`test` directories that should be committed. |
| `RL-SEC-001` | security | high; **critical** for private-key files | A sensitive file (`.env*`, SSH keys, `.pem`/`.key`/keystores, credential files) is present and not ignored. Critical when the name/extension denotes a private key, otherwise high. The file's contents are never read. Ignored sensitive files and safe templates such as `.env.example` do not trigger this rule. |

`.gitignore`-coverage checks (`004`–`006`, `010`, `012`, `RL-SEC-001`) evaluate only the root
`.gitignore`, matching discovery behavior.

## Dependencies (`dependency-manifests`)

Source: `src/repolens/analyzers/dependencies.py` over the inventory built by
`src/repolens/dependencies.py`. Supported manifests/lockfiles and limitations (best-effort
`pnpm-lock.yaml`, unparsed `bun.lock*`, simple-range-only semver proofs, `setup.py` never
audited) are listed in the README's "Dependency analysis details". Local-path, file, and VCS/URL
specifiers are treated as non-registry requirements and skipped by the registry checks rather
than flagged.

| Rule ID | Category | Severity | Trigger |
| --- | --- | --- | --- |
| `RL-DEP-001` | dependencies | medium | A dependency lockfile is malformed/unparseable. |
| `RL-DEP-002` | dependencies | medium | An invalid PEP 508 requirement in a requirements file. |
| `RL-DEP-003` | dependencies | low | An npm dependency is declared in `package.json` but absent from the lockfile in the same directory. |
| `RL-DEP-004` | dependencies | medium | The locked npm version is provably outside the declared range (simple `^`, `~`, `=`, exact ranges only). |
| `RL-DEP-005` | dependencies | info | Python runtime dependencies are neither exactly pinned nor locked. Advisory for libraries that intentionally ship ranges. |
| `RL-DEP-006` | dependencies | medium | Conflicting exact pins for the same Python distribution. |
| `RL-DEP-007` | dependencies | info | A lockfile format RepoLens cannot parse (for example `bun.lock`) — an audit coverage gap. Best-effort `pnpm-lock.yaml` inventories are marked incomplete and skip drift checks instead. |
| `RL-DEP-008` | dependencies | medium | A non-root dependency manifest is malformed. (Malformed *root* `pyproject.toml`/`package.json` are `RL-STRUCT-011`.) |

## Documentation (`documentation-consistency`)

Source: `src/repolens/analyzers/documentation.py`. Only the root `pyproject.toml` `readme` and
`license.file` declarations feed `001`/`002`; there are no checks for manifest `description` or
`author` presence, and no README section/content check beyond link targets.

| Rule ID | Category | Severity | Trigger |
| --- | --- | --- | --- |
| `RL-DOC-001` | documentation | medium | `pyproject.toml` declares a readme file that does not exist. |
| `RL-DOC-002` | documentation | medium | `pyproject.toml` declares a license file that does not exist. |
| `RL-DOC-003` | documentation | low | A relative link in the root README points at a path that does not exist (one finding per broken target). |
| `RL-DOC-004` | documentation | low | A declared SPDX license disagrees with the detected root LICENSE content. |
| `RL-DOC-005` | documentation | low | Manifests declare conflicting licenses. |

## Testing (`testing-hygiene`)

Source: `src/repolens/analyzers/testing.py`. These are static presence/configuration checks only;
tests are never executed and test dependencies are never installed. There is no CI-workflow
check.

| Rule ID | Category | Severity | Trigger |
| --- | --- | --- | --- |
| `RL-TEST-001` | testing | medium | Python sources are present but no recognizable Python tests were found. |
| `RL-TEST-002` | testing | medium | JS/TS sources are present but no recognizable JS/TS tests were found. |
| `RL-TEST-003` | testing | low | Tests exist but no runner is detected: no Python runner configuration, or no non-placeholder JS `test` script/runner setup. |
| `RL-TEST-004` | testing | info | A coverage tool is declared as a dependency but no coverage configuration was found. Does not fire merely because coverage is unconfigured when no coverage tool is declared. |
| `RL-TEST-005` | testing | low | Test code imports `pytest` but `pytest` is not declared as a dependency. |

## Python external tools (`ruff-python-lint`, `bandit-python-security`)

Both run only if the executable is already on the sanitized `PATH`; otherwise the analyzer outcome
is `unavailable`. Repository configuration is not loaded: Ruff runs
`check --isolated --no-cache --no-fix --output-format=json --select E4,E7,E9,F,B --target-version py311`;
Bandit runs `-f json -q --skip <list below>` from a disposable working directory. Both receive
only discovered, non-sensitive, non-oversized, non-ignored Python files.

### Ruff — `RUFF-<code>`, category `code_quality`

Severity assigned by RepoLens from the Ruff code (`python_lint._ruff_severity`):

| Ruff code | Severity | Confidence |
| --- | --- | --- |
| `invalid-syntax`, `E9*` | high | high |
| `F8*` | medium | high |
| Other `F*` | low | high |
| `B*` (flake8-bugbear) | medium | medium |
| Everything else in the selection (`E4*`, `E7*`) | low | medium |

### Bandit — `BANDIT-<test-id>`, category `security`

Skipped checks (false-positive-dominated in application/test code): `B101`, `B105`, `B106`,
`B110`, `B112`, `B311`, `B404`, `B603`, `B607`. Bandit's severity and confidence are mapped
directly (`HIGH`→high, `MEDIUM`→medium, `LOW`→low, `UNDEFINED`→low); CWE information is
preserved in the finding text where Bandit provides it.

## JavaScript/TypeScript (`biome-jsts-lint`)

`BIOME-<rule-short-name>` from a RepoLens-generated Biome config (`linter.rules.recommended`,
VCS/ignore-file integration disabled) passed with `--config-path`; project Biome configuration is
detected and reported in the outcome message but never loaded.

| Biome diagnostic severity | RepoLens severity |
| --- | --- |
| `error` | medium |
| `warning` (and any unrecognized value) | low |
| `information` / `info` / `hint` | info |

Category is `security` when the Biome rule path's second segment is `security` (for example
`lint/security/...`), otherwise `code_quality`.

## Known vulnerabilities (`osv-dependency-check`, opt-in)

Only runs a lookup when network checks are enabled (`--network-checks` /
`ScanConfig(enable_network_checks=True)`); otherwise it is `skipped` (or not applicable when no
locked packages exist). Rule ID is `OSV-<advisory-id>`, category `security`, one finding per
(advisory, package, version) — never claimed without an advisory ID returned by OSV.dev.

Severity resolution order (`osv._severity_from_advisory`):

1. The advisory's `database_specific.severity` string, if present — `CRITICAL`→critical,
   `HIGH`→high, `MODERATE`/`MEDIUM`→medium, `LOW`→low — with **high** confidence.
2. Otherwise the first CVSS `score` value that parses as a number: ≥ 9.0 critical, ≥ 7.0 high,
   ≥ 4.0 medium, ≥ 0.1 low — with **high** confidence.
3. Otherwise (including a `0.0`/unparsable score): **medium severity with low confidence**, and
   the finding explanation states that the rating is estimated. Unrated advisories are *not*
   downgraded to `info`.

Timeouts, connection/HTTP failures, and unreadable payloads are outcome states (`timed_out`,
`unavailable` marked coverage-incomplete, `failed`), never findings; see the README's
"Network-dependent behavior".
