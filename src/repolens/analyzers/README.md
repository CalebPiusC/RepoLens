# Analyzers Package

Each module here implements one (or, for `python_lint.py`, two) analyzers: independent checks
that examine the discovered repository through `RepositoryContext` and return `Finding` objects.
`ScanEngine` (`src/repolens/engine.py`) owns their lifecycle; the default suite is assembled by
`default_analyzers()` in this package's `__init__.py`.

## Base class

Analyzers subclass `Analyzer` in `base.py`. Only `name` and `analyze()` are abstract:

```python
class Analyzer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Stable machine-friendly identifier (AnalyzerOutcome.analyzer_name)."""

    def is_applicable(self, context: RepositoryContext) -> bool:
        """Default True. False -> outcome 'skipped' (not applicable)."""

    def skip_reason(self, context: RepositoryContext, config: ScanConfig) -> str | None:
        """Default None. Text -> deliberate, exit-neutral 'skipped' outcome."""

    def check_availability(self) -> AnalyzerAvailability:
        """Default available. Unavailable -> outcome 'unavailable'."""

    def completion_message(self) -> str | None:
        """Optional detail recorded on a 'completed' outcome."""

    def coverage_partial(self) -> bool:
        """True if a cap limited coverage; engine sets coverage_truncated."""

    @abstractmethod
    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        """Return findings. The engine builds the AnalyzerOutcome."""
```

Failure signaling uses exceptions from `base.py`, which the engine maps to outcomes:
`AnalyzerTimeoutError` → `timed_out`; `AnalyzerUnavailableError` (a check that started, then
could not complete) → `unavailable` with `coverage_incomplete=True`; `AnalyzerExecutionError` and
unexpected exceptions → `failed`. With `fail_fast=False` (default) one analyzer's failure never
aborts the others. Probing (`is_applicable`/`skip_reason`/`check_availability`) is isolated the
same way, and ordering matters: applicability first, then `skip_reason`, then availability.

## Default analyzers (in `default_analyzers()` order)

| # | Module | Class | `name` | Rule prefixes | External dependency |
| --- | --- | --- | --- | --- | --- |
| 1 | `structure.py` | `StructureAnalyzer` | `repolens-structure` | `RL-STRUCT-`, `RL-SEC-001` | None |
| 2 | `dependencies.py` | `DependencyAnalyzer` | `dependency-manifests` | `RL-DEP-` | None |
| 3 | `documentation.py` | `DocumentationAnalyzer` | `documentation-consistency` | `RL-DOC-` | None |
| 4 | `testing.py` | `TestingAnalyzer` | `testing-hygiene` | `RL-TEST-` | None |
| 5 | `python_lint.py` | `RuffAnalyzer` | `ruff-python-lint` | `RUFF-` | `ruff` on `PATH` |
| 6 | `python_lint.py` | `BanditAnalyzer` | `bandit-python-security` | `BANDIT-` | `bandit` on `PATH` |
| 7 | `jsts_lint.py` | `BiomeAnalyzer` | `biome-jsts-lint` | `BIOME-` | `biome` on `PATH` |
| 8 | `advisories.py` | `OsvVulnerabilityAnalyzer` | `osv-dependency-check` | `OSV-` | OSV.dev (only with `enable_network_checks`) |

Per-rule triggers and severity mappings: [docs/rules/README.md](../../../docs/rules/README.md).

## Shared helpers

- `tooling.py` — availability probing (`analyzer_availability()`, `--version` only), eligible-file
  selection with cap reporting, batching, disposable `tool_workspace()` directories outside the
  repository, path mapping back inside the root, and `run_tool()` over
  `subprocess_runner.run_safe_command()` (`shell=False`, sanitized environment, budgets).
  Repository tool configuration is never loaded; its presence is reported in outcome messages.
- `src/repolens/dependencies.py` (top level) — manifest/lockfile parsing into the inventory shared
  by `dependencies.py` and `advisories.py`.

## Adding an analyzer

See [docs/contributing/README.md](../../../docs/contributing/README.md#writing-a-new-analyzer) for
a runnable example, registration, rule-ID, testing, and documentation steps.
