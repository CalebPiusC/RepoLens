# Contributing to RepoLens

How to set up a development environment, run the checks CI runs, write a new analyzer, and submit
changes. Commands below match `.github/workflows/ci.yml` and were verified against
`pyproject.toml`.

## Development environment setup

RepoLens is built with the **hatchling** build backend. No Hatch environments are configured in
`pyproject.toml` (there is no `[tool.hatch.envs]` table), so do not use `hatch run` /
`hatch env create` — a default Hatch env would contain only runtime dependencies and commands
such as `pytest` would not be found. Use `pip` in a virtual environment, exactly as CI does.

Prerequisites: Python 3.11 or later and Git. Node.js/Biome are optional (only for exercising the
real Biome analyzer; tests stub it).

Clone the source, then create and activate an environment on Linux/macOS:

```sh
git clone https://github.com/CalebPiusC/RepoLens.git
cd RepoLens
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

In Windows PowerShell:

```powershell
git clone https://github.com/CalebPiusC/RepoLens.git
Set-Location RepoLens
py -3 -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

`python -m pip install ".[tools]"` installs just Ruff + Bandit alongside RepoLens; `dev` already
includes them. RepoLens is not published to PyPI. Editable installs are for development; the
[installation guide](../../README.md#installation) documents non-editable source installs.
Every CLI invocation also works as `python -m repolens …`.

## Running the checks (same as CI)

The existing quality CI (`.github/workflows/ci.yml`) has two jobs:

- **Quality (Ubuntu, Python 3.11/3.12/3.13):** Ruff lint, Ruff format check, strict mypy over
  `src` **and** `tests`, then pytest with coverage.
- **Tests (Windows, Python 3.11/3.12/3.13):** `python -m pytest -q` only.

The separate installation workflow (`.github/workflows/installation.yml`) builds and inspects
distributions and exercises non-editable installation, source updates, and uninstall on Linux and
Windows with Python 3.11–3.13. It needs GitHub and package-index access. There is no macOS job.

Run the full gate locally before pushing:

```bash
ruff check src tests
ruff format --check src tests      # auto-fix formatting with: ruff format src tests
mypy src tests                     # strict mode comes from pyproject.toml [tool.mypy]
pytest --cov=repolens --cov-report=term-missing
```

Notes:

- Use `mypy src tests`, not `mypy src` — the narrower command silently skips half the typed
  surface CI checks.
- Use `--cov=repolens` (the coverage `source` configured in `pyproject.toml`), not a filesystem
  path such as `--cov=src/repolens`.
- Current Ruff versions also format Python code blocks in Markdown files under `src/` and
  `tests/` (for example their package `README.md` files), so `ruff format --check src tests`
  covers those snippets too. Snippets under `docs/` are **not** checked by any gate — verify them
  manually (the analyzer example below was executed against the current API).

See [tests/README.md](../../tests/README.md) for test layout, stub tools, markers, and how to run
subsets. The default suite needs no network and no Ruff/Bandit/Biome installation.

## Versioning and distribution builds

`src/repolens/_version.py` is the **only** package-version source. Hatchling's built-in version
reader extracts the static string without importing RepoLens, including when building from an
sdist or GitHub archive with no `.git` directory. The CLI and report sources import the same
value. The JSON document schema remains separately versioned in `repolens.models`.

The main revision preceding this preparation used `0.1.1.dev0`; it was downloadable from source
but never published to PyPI. This preparation revision uses `0.1.1.dev1` so its source is distinct;
`0.1.1` is reserved for the separately approved first stable release. Multiple local commits can
still share a development version; pip may keep the earlier code in that case, so use the
documented `--force-reinstall` for same-version source updates.

Before distributing any later pre-release or release, choose a new PEP 440 version in
`_version.py`. Never publish different artifacts under an already published version; start the
next development cycle with a higher base version, for example `0.1.2.dev0` after `0.1.1`. Tags
and publishing are separate, explicit maintainer actions — this configuration does neither. See
the [release readiness checklist](../release/README.md) before the first release.

For a local packaging check (no upload):

```sh
python -m pip install build twine
SOURCE_DATE_EPOCH=1735689600 python -m build
python -m twine check dist/*
```

In PowerShell, set `$env:SOURCE_DATE_EPOCH = "1735689600"` before `python -m build` and run
`python -m twine check dist/*`. Clean old artifacts out of `dist/` first when checking a new build.
The build backend is pinned and reproducible timestamps are enabled. CI compares two builds with
the same source, epoch, and toolchain; this is not a fully hermetic dependency lock or a promise
that different platforms or build dependency versions produce identical bytes.

The wheel and sdist select package Python sources and `py.typed`, not the whole checkout. Hatchling
also includes the project README, license, build metadata, and tracked `.gitignore` in the sdist.
If adding required non-Python package data, update the allowlists for **both** targets and their
artifact checks. Review the archive contents before any future release; local settings, credentials,
tests, caches, and unrelated files must not be shipped.

## Writing a new analyzer

Analyzers live in `src/repolens/analyzers/` and subclass **`Analyzer`** from
`analyzers/base.py` (there is no `BaseAnalyzer`). Only two members are abstract: the read-only
`name` property and `analyze()`. Everything else has a safe default you override only when
needed:

| Member | Contract |
| --- | --- |
| `name` (property) | Stable machine-friendly ID, e.g. `"ruff-python-lint"`. Appears as `AnalyzerOutcome.analyzer_name`. |
| `is_applicable(context) -> bool` | Default `True`. Return `False` when the repository has nothing for you (outcome: `skipped`). |
| `skip_reason(context, config) -> str \| None` | Default `None`. Return text for a deliberate, exit-neutral skip (for example an opt-in that was not enabled). Takes precedence over unavailability for the recorded outcome. |
| `check_availability() -> AnalyzerAvailability` | Default available. For external tools, return `analyzer_availability("<tool>")` from `analyzers/tooling.py` (outcome when unavailable: `unavailable`, exit-neutral). |
| `analyze(context, config) -> list[Finding]` | Do the work and return findings. The engine builds the `AnalyzerOutcome`; you never return one. Raise `AnalyzerTimeoutError` / `AnalyzerUnavailableError` / `AnalyzerExecutionError` (from `analyzers/base.py`) for the corresponding failure modes — see `tooling.run_tool()`, which already maps subprocess failures for you. |
| `completion_message() -> str \| None` | Optional detail recorded when the analyzer returns findings. |
| `reporting_failure() -> str \| None` | Reason the returned findings are incomplete; the engine records `failed` but retains confirmed findings. |
| `coverage_partial() -> bool` | Return `True` when a cap meant only part of the eligible files were covered; the engine records `coverage_truncated` on a completed outcome. |

`context` is a `RepositoryContext` (`repolens.discovery`): use `context.files`,
`context.files_by_path`, `context.has_file()`, and `context.read_text()` — never open repository
paths directly, so symlink, sensitive-file, and size protections apply. Cap your output at
`config.max_findings_per_analyzer` and honor the budgets in `ScanConfig` instead of hard-coding
limits. Reset per-run reporting state with `_reset_reporting()` at the start of `analyze()`, and
use `_limit_findings()` to report actual omissions rather than treating an exact cap as loss.
For other output loss, `_mark_reporting_failure()` records a reason while preserving findings.
For unexamined eligible files, use `coverage_partial()`; do not broaden its JSON field meaning.

A minimal, working example (flags a missing file; adapt names and rules):

```python
from __future__ import annotations

from repolens.analyzers.base import Analyzer
from repolens.config import ScanConfig
from repolens.discovery import RepositoryContext
from repolens.models import (
    Category,
    Confidence,
    Finding,
    FindingSource,
    Severity,
    SourceKind,
)

_SOURCE = FindingSource(
    kind=SourceKind.DETERMINISTIC,
    tool="repolens-example",
    tool_version="0.1.0",
)


class ExampleAnalyzer(Analyzer):
    """Flag repositories that do not contain an EXAMPLE.txt file."""

    @property
    def name(self) -> str:
        return "example-check"

    def is_applicable(self, context: RepositoryContext) -> bool:
        return bool(context.files)

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        if context.has_file("EXAMPLE.txt"):
            return []
        return [
            Finding(
                rule_id="RL-EX-001",
                category=Category.STRUCTURE,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="Missing EXAMPLE.txt file",
                evidence="No EXAMPLE.txt file was found in the repository.",
                explanation=(
                    "This example check expects every repository to carry an "
                    "EXAMPLE.txt file at its root."
                ),
                recommendation="Add an EXAMPLE.txt file at the repository root.",
                verification="Confirm EXAMPLE.txt exists at the repository root.",
                source=_SOURCE,
            )
        ]
```

Then:

1. **Choose rule IDs.** Pick a stable prefix that does not collide with the
   [rules reference](../rules/README.md) (`RL-STRUCT`, `RL-SEC`, `RL-DEP`, `RL-DOC`, `RL-TEST`,
   `RUFF-`, `BANDIT-`, `BIOME-`, `OSV-`). Rule IDs, severities, and categories become part of the
   JSON contract; changing a meaning later has schema-version implications (see below).
2. **Register it** in `default_analyzers()` in `src/repolens/analyzers/__init__.py` (and export
   the class in `__all__`). Keep deterministic offline analyzers ahead of external-tool and
   network analyzers. For one-off embedding, `ScanEngine(analyzers=[...])` accepts any explicit
   sequence without touching the default suite.
3. **External tools** must go through `analyzers/tooling.py` + `subprocess_runner.run_safe_command()`
   (structured argv, `shell=False`, sanitized env, disposable workspace, budgets). Never load the
   target repository's tool configuration, never execute repository code, and map tool-reported
   paths back inside the root with `repository_relative_path()`.
4. **Write tests** (see [tests/README.md](../../tests/README.md)): applicability, triggering and
   non-triggering fixtures via `make_python_repo`/`make_jsts_repo`, unavailable-tool behavior via
   `install_fake_tool` stubs, and any partial-coverage flagging. New security invariants belong in
   `tests/security/`.
5. **Document it:** add the rules to [docs/rules/README.md](../rules/README.md), the analyzer row
   to [src/repolens/analyzers/README.md](../../src/repolens/analyzers/README.md) (real `name`
   value!), the README "Supported checks" summary if applicable, and a line under `[Unreleased]`
   in [docs/changelog/README.md](../changelog/README.md).

### JSON schema changes

The JSON document is `ScanReport.model_dump(mode="json")` plus `result`, versioned by
`repolens.models.SCHEMA_VERSION` (currently `1.1.0`). If you change model fields, enum values, or
field meanings:

- Bump `SCHEMA_VERSION` per the policy in the README's "Schema versioning" (additive → MINOR,
  breaking → MAJOR) and update `SUPPORTED_SCHEMA_MAJOR_VERSIONS` reasoning if needed.
- Update the README JSON section and `tests/unit/test_json_output.py` in the same change.
- Remember `strict=False` parsing tolerates unknown *members* but must keep refusing unknown
  *values* — do not weaken `UnsupportedSchemaValueError` handling to make a test pass.

## Commit messages

Recent history mostly uses Conventional-Commits-style subjects — `feat(cli): …`,
`fix(discovery): …`, `docs: …`, `test: …`, `chore: …` — but this is a convention, not a check
enforced by CI. Follow it where it fits: imperative mood, concise subject, scope when it helps,
and a body explaining *why* for non-trivial changes.

## Pull request process

1. Branch from `main` with a descriptive name. Keep the change focused; documentation PRs should
   not change application code, tests, or committed assets (for example images counted by the
   self-scan) without calling that out explicitly.
2. Run the full gate above at the **final** head of your branch — results from an earlier commit
   do not describe the branch after later commits (including binary/asset changes, which the
   repository self-scan test can see).
3. Verify documentation claims against the code: run documented commands, execute code snippets,
   and check relative links. Never weaken or delete a test to accommodate documentation or assets;
   fix the asset/content instead and say so in the PR.
4. Describe what changed, why, and how you verified it, with actual command output (test counts,
   coverage) for the head commit. If you add or retire documentation, say where the information
   lives now so nothing is silently lost.
5. Expect review feedback as additional commits on the same branch. Merging is the maintainer's
   call; merged PRs to date use merge commits.

## Reporting security issues

Do not open a public issue for a vulnerability in RepoLens itself. See the
[security model](../security/README.md#reporting-a-vulnerability-in-repolens) and the root
[SECURITY.md](../../SECURITY.md).
