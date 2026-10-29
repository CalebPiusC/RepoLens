# Test Suite

This document describes the organisation of the RepoLens test suite, how to run subsets of tests, and what assumptions the tests make about the environment.

---

## Directory Structure

```
tests/
  conftest.py              Shared fixtures: temporary directories, stub executables,
                           sample file trees, ScanConfig overrides.
  unit/                    Unit tests for individual modules and functions.
  integration/             End-to-end tests that exercise the full scan pipeline.
  security/                Tests that verify security invariants: symlink safety,
                           subprocess isolation, redaction correctness.
```

### `unit/`

Unit tests target individual functions and classes in isolation. Dependencies on the filesystem are provided through `tmp_path` fixtures. Dependencies on external tools are replaced by stub executables.

Each unit test file corresponds to one source module or one cohesive area of behaviour. Examples: `test_discovery.py` covers the discovery walk logic, `test_redaction.py` covers the redaction patterns, `test_models.py` covers Pydantic model validation.

### `integration/`

Integration tests exercise the complete scan pipeline from the CLI entry point or from `ScanEngine.scan()` down to the assembled `ScanReport`. They use real (temporary) file trees on disk.

| File | What it tests |
|---|---|
| `test_cli_entry_point.py` | CLI argument parsing, exit codes, and stdout format for a set of representative repository fixtures. |
| `test_stage2_scan.py` | Full scan pipeline including the dependency, documentation, testing, and lint analyzers against fixture repositories. |

### `security/`

Security tests verify that specific threat scenarios are handled correctly and cannot be exploited. They are kept separate from unit and integration tests so they can be run independently and so their purpose is immediately clear.

| File | What it tests |
|---|---|
| `test_discovery_safety.py` | Symlink rejection (files and directories), `O_NOFOLLOW` enforcement, sensitive file exclusion, depth limit enforcement, byte cap enforcement. |
| `test_stage2_safety.py` | That no code from the target repository is executed during a full Stage 2 scan. |
| `test_subprocess_and_redaction.py` | That `SubprocessRunner` uses `shell=False`, that the child environment contains only allowlisted variables, and that evidence containing secrets is redacted before it appears in findings. |

---

## Stub Executables

The `python_lint.py` and `jsts_lint.py` analyzers invoke Ruff, Bandit, and Biome as subprocesses. The test suite does not require these tools to be installed. Instead, `conftest.py` provides fixtures that create stub executables in temporary directories and prepend those directories to `PATH` for the duration of the test.

Stub executables are small shell scripts or Python scripts that write a fixed JSON or text response to stdout and exit with a configured exit code. This allows tests to verify that the analyzer correctly parses tool output without depending on the real tool being installed or producing consistent output across versions.

---

## Pytest Markers

| Marker | Meaning |
|---|---|
| `network` | Test requires outbound network access to OSV.dev. Not run by default. |

To run only network tests:

```bash
pytest -m network
```

To explicitly exclude network tests (the default in CI without the `--network-checks` environment):

```bash
pytest -m "not network"
```

---

## Running the Test Suite

**Run everything**:

```bash
hatch run pytest
```

**Run with coverage**:

```bash
hatch run pytest --cov=src/repolens --cov-report=term-missing
```

**Run one directory**:

```bash
hatch run pytest tests/security
hatch run pytest tests/unit
hatch run pytest tests/integration
```

**Run one file**:

```bash
hatch run pytest tests/security/test_discovery_safety.py
```

**Run one test by name**:

```bash
hatch run pytest -k test_symlink_directory_is_rejected
```

**Run with verbose output**:

```bash
hatch run pytest -v
```

---

## What Is Not Required

- **Ruff** does not need to be installed to run the test suite. Tests for `python_lint.py` use stub executables.
- **Bandit** does not need to be installed. Same as Ruff.
- **Biome** does not need to be installed. Tests for `jsts_lint.py` use stub executables.
- **Network access** is not required. Tests marked `network` are skipped by default.
- **Root or administrator privileges** are not required for any test.
- **Docker** is not required.
