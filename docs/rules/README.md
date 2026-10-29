# Rules Reference

This document lists every rule ID produced by RepoLens, grouped by category. Each entry includes the rule ID, default severity, and a concise description. Severity levels from highest to lowest are: `critical`, `high`, `medium`, `low`, `info`.

---

## Severity Thresholds

The CLI accepts a `--min-severity` flag that filters the output to findings at or above the specified level. The default threshold is `info`, meaning all findings are shown. Setting `--min-severity medium` hides `low` and `info` findings. The exit code is 1 if any finding at or above the threshold is present; 0 otherwise.

---

## Finding Fingerprints

Each finding carries a `fingerprint` field: a SHA-256 hash derived from the `rule_id`, `location`, and a normalised form of the `evidence`. The fingerprint is stable across scans of the same repository state, enabling deduplication and change tracking. It is not affected by scan timestamp, duration, or report schema version.

---

## Structure (`RL-STRUCT`)

| Rule ID | Severity | Description |
|---|---|---|
| `RL-STRUCT-001` | medium | No LICENSE file found at the repository root. |
| `RL-STRUCT-002` | low | No README file found at the repository root. |
| `RL-STRUCT-003` | low | No `.gitignore` file found at the repository root. |
| `RL-STRUCT-004` | high | A sensitive file (e.g., `.env`, SSH key, PEM) is not covered by `.gitignore`. |
| `RL-STRUCT-005` | medium | A vendor directory (e.g., `vendor/`) is not covered by `.gitignore`. |
| `RL-STRUCT-006` | low | No project manifest found (no `pyproject.toml`, `package.json`, `setup.cfg`, or `Pipfile`). |
| `RL-STRUCT-007` | medium | A lockfile is absent for a manifest that declares dependencies. |
| `RL-STRUCT-008` | low | Binary or compiled files with significant size are committed to the repository. |
| `RL-STRUCT-009` | low | The `.gitignore` file excludes files that should be committed (e.g., manifest or lockfile). |
| `RL-STRUCT-010` | info | A build output directory (e.g., `dist/`, `build/`) is present and not ignored. |
| `RL-STRUCT-011` | info | A cache directory (e.g., `__pycache__/`, `.mypy_cache/`) is committed to the repository. |
| `RL-STRUCT-012` | medium | A secrets-bearing file pattern was detected inside the repository tree. |

---

## Dependencies (`RL-DEP`)

| Rule ID | Severity | Description |
|---|---|---|
| `RL-DEP-001` | high | A dependency is declared without a pinned version or version constraint. |
| `RL-DEP-002` | medium | A lockfile is outdated relative to the manifest (manifest declares a package not present in the lockfile). |
| `RL-DEP-003` | high | A dependency is sourced from a VCS URL (git+, hg+, etc.) without a pinned commit hash. |
| `RL-DEP-004` | medium | A dependency is sourced from a local path, which may not be reproducible outside this machine. |
| `RL-DEP-005` | info | Duplicate dependency declarations found across multiple manifest files. |
| `RL-DEP-006` | medium | Development dependencies are not separated from production dependencies in the manifest. |
| `RL-DEP-007` | low | The lockfile format could not be fully parsed; coverage may be incomplete. |
| `RL-DEP-008` | info | Multiple package managers appear to be in use simultaneously (e.g., both `yarn.lock` and `package-lock.json`). |

---

## Documentation (`RL-DOC`)

| Rule ID | Severity | Description |
|---|---|---|
| `RL-DOC-001` | low | The README references a file by relative path that does not exist in the repository. |
| `RL-DOC-002` | medium | The LICENSE file contains an SPDX identifier that does not match the `license` field in the project manifest. |
| `RL-DOC-003` | low | The manifest `description` field is absent or empty. |
| `RL-DOC-004` | low | The manifest `author` or `authors` field is absent. |
| `RL-DOC-005` | info | The README does not contain an installation section (no heading matching "install" or "getting started"). |

---

## Testing (`RL-TEST`)

| Rule ID | Severity | Description |
|---|---|---|
| `RL-TEST-001` | medium | No test files found in the repository. |
| `RL-TEST-002` | low | No test runner configuration found (no `pytest.ini`, `[tool.pytest]` in `pyproject.toml`, or equivalent). |
| `RL-TEST-003` | low | No coverage configuration found (no `.coveragerc`, `[tool.coverage]` in `pyproject.toml`, or equivalent). |
| `RL-TEST-004` | low | The primary test runner (pytest) is not declared as a development dependency. |
| `RL-TEST-005` | info | Test files are present but no CI workflow file was found to run them automatically. |

---

## Code Quality: Python (`RUFF-`, `BANDIT-`)

Ruff and Bandit produce findings using their own rule IDs. RepoLens prefixes them to make the source unambiguous.

### Ruff

RepoLens enables the following Ruff rule groups: `E4` (import errors), `E7` (statement errors), `E9` (runtime errors), `F` (Pyflakes), `B` (flake8-bugbear). Findings are reported as `RUFF-<code>`, for example `RUFF-F401` (unused import) or `RUFF-B006` (mutable default argument).

Severity is assigned by RepoLens based on rule category:

| Ruff group | Assigned severity |
|---|---|
| `E9` (runtime errors) | high |
| `E4`, `E7`, `F`, `B` | medium |

### Bandit

RepoLens runs Bandit with the following rules skipped (because they produce excessive noise for typical repositories or have alternative mitigations in place): `B101`, `B105`, `B106`, `B110`, `B112`, `B311`, `B404`, `B603`, `B607`. Findings are reported as `BANDIT-<id>`, for example `BANDIT-B201` (Flask debug mode) or `BANDIT-B501` (disabled TLS verification).

Severity mapping from Bandit's native severity levels:

| Bandit severity | Assigned severity |
|---|---|
| HIGH | high |
| MEDIUM | medium |
| LOW | low |

---

## Code Quality: JavaScript and TypeScript (`BIOME-`)

RepoLens generates its own Biome configuration using the recommended rule set with VCS integration disabled. Findings are reported as `BIOME-<rule>`, where `<rule>` matches the Biome rule name (for example `BIOME-noExplicitAny` or `BIOME-useConst`). Severity is derived from Biome's native rule severity classification.

---

## Security Advisories (`OSV-`)

When `--network-checks` is enabled, the advisories analyzer queries OSV.dev and reports findings using the advisory's own identifier as the rule ID: `OSV-<advisory-id>` (for example `OSV-GHSA-xxxx-xxxx-xxxx`). Severity is mapped from the OSV advisory's CVSS score:

| CVSS score range | Assigned severity |
|---|---|
| 9.0 and above | critical |
| 7.0 to 8.9 | high |
| 4.0 to 6.9 | medium |
| Below 4.0 | low |
| No score available | info |
