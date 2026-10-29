# Analyzers Package

This package contains all analyzer modules for RepoLens. Each analyzer is an independent unit that examines one aspect of a repository and produces zero or more `Finding` objects. The `ScanEngine` in `engine.py` manages the lifecycle of all analyzers.

---

## Base Class

All analyzers extend `BaseAnalyzer` defined in `base.py`. The interface is:

```python
class BaseAnalyzer(ABC):
    name: str
    # A stable identifier used as the key in ScanReport.analyzer_outcomes.

    @abstractmethod
    def is_applicable(self, summary: DiscoverySummary) -> bool:
        """
        Return True if this analyzer has relevant files to work on.
        For example, the JS/TS linter returns False for a Python-only repository.
        Called before check_availability(); if False, the analyzer is skipped
        without checking whether the tool is installed.
        """

    @abstractmethod
    def check_availability(self) -> bool:
        """
        Return True if all required external tools are installed and reachable.
        Called only when is_applicable() returns True.
        If False, the analyzer outcome is recorded as 'unavailable'.
        """

    @abstractmethod
    def skip_reason(self) -> str:
        """
        Return a human-readable explanation of why the analyzer was skipped
        or is unavailable. Used in the report's analyzer outcome section.
        """

    @abstractmethod
    def analyze(
        self,
        path: Path,
        files: list[Path],
        config: ScanConfig,
    ) -> tuple[AnalyzerOutcome, list[Finding]]:
        """
        Perform the analysis. Return an AnalyzerOutcome and the list of findings.
        Must not raise: catch all exceptions internally and record them in the outcome.
        """

    def coverage_partial(self) -> bool:
        """
        Return True if the analyzer produced findings but could not examine
        all relevant files (for example, due to a file count cap).
        Optional override; defaults to False.
        """

    def completion_message(self) -> str:
        """
        Return a short human-readable status message for completed runs.
        Optional override.
        """
```

---

## Analyzer Lifecycle (managed by ScanEngine)

For each analyzer, `ScanEngine` executes the following steps in order:

1. Call `is_applicable(summary)`. If `False`, record outcome as `skipped` with `skip_reason()` and move to the next analyzer.
2. Call `check_availability()`. If `False`, record outcome as `unavailable` with `skip_reason()` and move to the next analyzer.
3. Call `analyze(path, files, config)` inside a try/except block. If an exception escapes `analyze()`, record outcome as `failed` with the redacted exception message.
4. If `analyze()` returns successfully, record the returned `AnalyzerOutcome` and append all returned `Finding` objects to the report's finding list.

This lifecycle means that an exception in one analyzer never aborts the remaining analyzers.

---

## Analyzers

| Module | `name` | Rule Prefix | External Tool | Description |
|---|---|---|---|---|
| `structure.py` | `structure` | `RL-STRUCT` | None | Repository hygiene: LICENSE, README, `.gitignore` coverage, unignored secrets, manifests, lockfiles, binary bloat. |
| `python_lint.py` | `python_lint` | `RUFF-`, `BANDIT-` | `ruff`, `bandit` | Static analysis of Python files using Ruff and Bandit. Both run with `shell=False` in disposable working directories. |
| `jsts_lint.py` | `jsts_lint` | `BIOME-` | `biome` | Static analysis of JavaScript and TypeScript files using Biome with a RepoLens-generated configuration. |
| `dependencies.py` | `dependencies` | `RL-DEP` | None | Parses Python and npm manifests and lockfiles. Checks for missing pins, absent lockfiles, VCS sources, and package manager conflicts. |
| `documentation.py` | `documentation` | `RL-DOC` | None | Validates README relative links, SPDX license consistency, and manifest metadata completeness. |
| `testing.py` | `testing` | `RL-TEST` | None | Checks for test file presence, runner and coverage configuration, and test runner as a declared dependency. |
| `advisories.py` | `advisories` | `OSV-` | OSV.dev API (opt-in) | Queries OSV.dev for known vulnerabilities in resolved dependencies. Skipped unless `ScanConfig.enable_network_checks` is True. |

---

## Adding a New Analyzer

See the [Contributing Guide](../../../docs/contributing/README.md) for step-by-step instructions on implementing `BaseAnalyzer`, choosing a rule ID prefix, writing tests, and registering the analyzer with `ScanEngine`.
