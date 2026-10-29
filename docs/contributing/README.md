# Contributing to RepoLens

Thank you for your interest in contributing. This document describes how to set up a development environment, run the test suite, write a new analyzer, and submit changes.

---

## Development Environment Setup

RepoLens uses [Hatch](https://hatch.pypa.io/) as its project manager and build backend. You do not need to create a virtualenv manually; Hatch manages it.

**Prerequisites**:

- Python 3.11 or later
- `pip install hatch` (or `pipx install hatch`)
- Git

**Clone and enter the repository**:

```bash
git clone https://github.com/CalebPiusC/RepoLens.git
cd RepoLens
```

**Install the project in development mode**:

```bash
hatch env create
```

This creates a managed virtual environment and installs RepoLens along with all development dependencies (pytest, mypy, ruff, etc.).

**Activate a shell inside the environment** (optional, for direct tool access):

```bash
hatch shell
```

Alternatively, prefix commands with `hatch run` to run them inside the environment without activating it.

---

## Running Tests

The test suite uses pytest. All tests are in the `tests/` directory, divided into `unit/`, `integration/`, and `security/` subdirectories.

**Run the full test suite**:

```bash
hatch run pytest
```

**Run only unit tests**:

```bash
hatch run pytest tests/unit
```

**Run only security tests**:

```bash
hatch run pytest tests/security
```

**Run only integration tests**:

```bash
hatch run pytest tests/integration
```

**Run with coverage**:

```bash
hatch run pytest --cov=src/repolens --cov-report=term-missing
```

**Run tests that require network access** (disabled by default with the `network` marker):

```bash
hatch run pytest -m network
```

External tools (Ruff, Bandit, Biome) are not required to run the test suite. Tests for `python_lint.py` and `jsts_lint.py` use stub executables to simulate tool output.

---

## Linting and Type Checking

**Run Ruff linting**:

```bash
hatch run ruff check src tests
```

**Run Ruff format check**:

```bash
hatch run ruff format --check src tests
```

**Auto-format with Ruff**:

```bash
hatch run ruff format src tests
```

**Run mypy strict type checking**:

```bash
hatch run mypy src
```

All of these checks run in CI and must pass before a pull request can be merged. Run them locally before pushing.

---

## Writing a New Analyzer

Analyzers live in `src/repolens/analyzers/`. Each analyzer is a class that extends `BaseAnalyzer` (defined in `analyzers/base.py`).

### Step 1: Create the module

Create a new file, for example `src/repolens/analyzers/my_check.py`.

### Step 2: Implement the interface

```python
from repolens.analyzers.base import BaseAnalyzer
from repolens.models import AnalyzerOutcome, Finding, ScanConfig, DiscoverySummary
from pathlib import Path

class MyCheckAnalyzer(BaseAnalyzer):
    name = "my_check"

    def is_applicable(self, summary: DiscoverySummary) -> bool:
        # Return False if this analyzer has nothing to do for this repository.
        return True

    def check_availability(self) -> bool:
        # Return False if a required external tool is not installed.
        return True

    def skip_reason(self) -> str:
        # Return a human-readable reason why this analyzer was skipped.
        return "My check is not applicable to this repository."

    def analyze(
        self,
        path: Path,
        files: list[Path],
        config: ScanConfig,
    ) -> tuple[AnalyzerOutcome, list[Finding]]:
        findings: list[Finding] = []
        # ... perform checks, append Finding objects to findings ...
        outcome = AnalyzerOutcome(status="completed", duration_ms=0)
        return outcome, findings
```

### Step 3: Choose rule IDs

Pick a stable rule ID prefix that does not conflict with existing prefixes (see the [Rules Reference](../rules/README.md)). Rule IDs must be stable across versions because users may suppress or filter by them.

### Step 4: Register the analyzer

Add an instance of your analyzer to the default analyzer list in `engine.py` (or wherever the default list is assembled). If the analyzer is opt-in, document the condition under which it is included.

### Step 5: Write tests

Add tests in `tests/unit/`. Test `is_applicable()` with different `DiscoverySummary` inputs. Test `analyze()` with both fixtures that should and should not trigger the rule. Test that `check_availability()` returns `False` gracefully when the tool is absent.

### Step 6: Document the rules

Add the new rule IDs to `docs/rules/README.md` with their category, severity, and description.

---

## Commit Message Conventions

RepoLens uses the [Conventional Commits](https://www.conventionalcommits.org/) format.

**Format**:

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

**Types**:

| Type | When to use |
|---|---|
| `feat` | A new feature or analyzer. |
| `fix` | A bug fix. |
| `docs` | Documentation changes only. |
| `test` | Adding or correcting tests. |
| `refactor` | Code change that neither fixes a bug nor adds a feature. |
| `chore` | Maintenance tasks (dependency updates, CI config). |
| `perf` | Performance improvements. |

**Scope** (optional): the affected module or area, for example `discovery`, `analyzers`, `cli`, `deps`.

**Examples**:

```
feat(analyzers): add Go module dependency parser

fix(discovery): reject symlinks encountered after initial stat

docs(adr): add ADR-006 for future lockfile pinning requirement

test(security): add symlink escape integration test
```

Keep the short description under 72 characters. Use the imperative mood ("add", "fix", "remove", not "added", "fixed", "removed").

---

## Pull Request Process

1. **Fork the repository** and create a branch from `main`. Name branches descriptively: `feat/go-analyzer`, `fix/discovery-depth-off-by-one`, `docs/contributing-guide`.

2. **Make your changes** and ensure all of the following pass locally:
   - `hatch run pytest`
   - `hatch run ruff check src tests`
   - `hatch run ruff format --check src tests`
   - `hatch run mypy src`

3. **Write or update tests** for every changed behaviour. New analyzers must have unit tests covering the rule trigger and the no-trigger case.

4. **Update documentation**:
   - If you added a new rule, add it to `docs/rules/README.md`.
   - If you made a significant design decision, consider writing an ADR in `docs/adr/`.
   - Update `docs/changelog/README.md` under the `[Unreleased]` section.

5. **Open a pull request** against `main`. Fill in the PR description with:
   - What the change does.
   - Why it is needed.
   - How to test it manually if automated tests do not cover it fully.

6. **Address review feedback** by pushing additional commits to the same branch. Do not force-push after review has begun unless specifically asked to do so.

7. **Squash and merge** is the preferred merge strategy. The maintainer will handle this after approval.
