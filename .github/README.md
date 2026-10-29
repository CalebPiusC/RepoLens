# GitHub Actions Workflows

This directory contains the CI configuration for RepoLens. All workflows are defined in `workflows/ci.yml`.

---

## Workflow Overview

The CI workflow (`ci.yml`) runs on every push and pull request to `main`. It consists of two jobs: `quality` and `windows-tests`.

---

## Job: `quality`

**Runs on**: `ubuntu-latest`

**Python versions tested**: 3.11, 3.12, 3.13 (matrix strategy)

**Steps**:

1. **Checkout**: Checks out the repository.
2. **Set up Python**: Installs the specified Python version from the matrix.
3. **Install Hatch**: Installs the Hatch project manager.
4. **Ruff lint**: Runs `ruff check src tests`. Fails if any linting violation is found.
5. **Ruff format check**: Runs `ruff format --check src tests`. Fails if any file is not correctly formatted.
6. **mypy**: Runs `mypy --strict src`. Fails if any type error is found. This step runs on Python 3.11 only (type annotations are identical across versions, and running mypy on all three would be redundant).
7. **pytest with coverage**: Runs the full test suite with coverage reporting. Fails if any test fails. Coverage is reported to the terminal but not enforced at a specific threshold in the current version.

---

## Job: `windows-tests`

**Runs on**: `windows-latest`

**Python versions tested**: 3.11, 3.12, 3.13 (matrix strategy)

**Steps**:

1. **Checkout**: Checks out the repository.
2. **Set up Python**: Installs the specified Python version.
3. **Install Hatch**: Installs Hatch.
4. **pytest**: Runs the full test suite. The purpose of this job is to verify that Windows-specific code paths in `SubprocessRunner` (Job Object process-group termination, Windows path handling) function correctly.

Ruff and mypy are not repeated on Windows because their output is platform-independent. Only the test suite runs on Windows to verify runtime behaviour.

---

## Python Version Matrix

| Python | quality (Ubuntu) | windows-tests |
|---|---|---|
| 3.11 | Yes | Yes |
| 3.12 | Yes | Yes |
| 3.13 | Yes | Yes |

---

## Interpreting CI Failures

**Ruff lint failure**: A linting rule was violated in `src/` or `tests/`. Run `hatch run ruff check src tests` locally to see the violations and `hatch run ruff check --fix src tests` to auto-fix those that can be fixed automatically.

**Ruff format failure**: A file is not formatted according to Ruff's formatter. Run `hatch run ruff format src tests` locally to apply the correct formatting.

**mypy failure**: A type error was introduced. Run `hatch run mypy src` locally to see the error. All mypy errors must be resolved; `type: ignore` comments are acceptable only in exceptional cases and must include a reason.

**pytest failure on Ubuntu**: A test is failing. Run `hatch run pytest -v` locally with the same Python version to reproduce. If the failure is in a security test, read `tests/security/` for context on what invariant is being verified.

**pytest failure on Windows**: A Windows-specific code path is broken. This is most commonly in `subprocess_runner.py` or in path-handling code. Reproduce by running the test suite on a Windows machine or in a Windows Docker container. Look for differences in path separators, process group handling, or environment variable behaviour.

**A job passes on Ubuntu but fails on Windows**: This almost always indicates a platform-specific assumption in the code. Common causes: hardcoded `/` path separators, POSIX-specific `os` calls, or assumptions about environment variable availability on Windows.
