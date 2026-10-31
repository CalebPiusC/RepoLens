"""Static testing-hygiene analyzer.

Checks whether a repository has recognizable tests, a way to run them, and coverage
configuration when coverage tooling is declared. No tests are executed and no test
dependencies are installed.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import PurePosixPath
from typing import Any, cast

from repolens import __version__
from repolens.analyzers.base import Analyzer
from repolens.config import ScanConfig
from repolens.dependencies import DependencyInventory, Ecosystem, build_dependency_inventory
from repolens.discovery import DiscoveredFile, RepositoryContext
from repolens.exceptions import DiscoveryError, OversizedFileAccessError, SensitiveFileAccessError
from repolens.models import (
    Category,
    Confidence,
    DetectedLanguage,
    Finding,
    FindingLocation,
    FindingSource,
    Severity,
    SourceKind,
)

_SOURCE = FindingSource(
    kind=SourceKind.DETERMINISTIC,
    tool="repolens-testing",
    tool_version=__version__,
)

_PYTHON_SUFFIXES = frozenset({".py"})
_JS_TS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
_TEST_DIR_NAMES = frozenset({"test", "tests", "__tests__", "spec", "__spec__", "cypress", "e2e"})
_PY_TEST_FILE_RE = re.compile(r"^(?:test_.+|.+_test|conftest)\.py$")
_JS_TEST_FILE_RE = re.compile(r"^.+\.(?:test|spec|cy)\.[cm]?[jt]sx?$")

_PYTHON_RUNNERS = frozenset({"pytest", "pytest-cov", "tox", "nox", "nose", "nose2", "unittest"})
_JS_RUNNERS = frozenset(
    {
        "vitest",
        "jest",
        "mocha",
        "ava",
        "tap",
        "jasmine",
        "karma",
        "playwright",
        "@playwright/test",
        "cypress",
        "node-tap",
        "uvu",
    }
)
_COVERAGE_TOOLS = frozenset(
    {
        "pytest-cov",
        "coverage",
        "nyc",
        "c8",
        "@vitest/coverage-v8",
        "@vitest/coverage-istanbul",
    }
)
_PYTHON_RUNNER_FILES = frozenset({"pytest.ini", "tox.ini", "noxfile.py", "conftest.py"})
_JS_RUNNER_FILE_PREFIXES = (
    "vitest.config.",
    "jest.config.",
    "playwright.config.",
    "cypress.config.",
    ".mocharc",
)
_COVERAGE_FILE_NAMES = frozenset({".coveragerc", "codecov.yml", ".codecov.yml"})
_MAX_TEST_FILES_READ = 20
_MAX_TEST_BYTES = 131_072


def _as_mapping(value: object) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _is_test_path(path: str) -> bool:
    posix = PurePosixPath(path)
    if any(part.lower() in _TEST_DIR_NAMES for part in posix.parts[:-1]):
        return True
    return bool(_PY_TEST_FILE_RE.match(posix.name) or _JS_TEST_FILE_RE.match(posix.name))


def _suffix(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


def _eligible(context: RepositoryContext, item: DiscoveredFile) -> bool:
    return not (
        item.is_sensitive
        or item.is_oversized
        or (context.has_gitignore and context.gitignore.is_ignored(item.path, is_dir=False))
    )


def _safe_text(context: RepositoryContext, path: str) -> str | None:
    """Distinguish an empty file from an input that became unavailable."""
    try:
        return context.read_text(path)
    except (DiscoveryError, OversizedFileAccessError, SensitiveFileAccessError, OSError):
        return None


def _truncate(text: str, limit: int) -> str:
    cleaned = " ".join(text.split())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3].rstrip() + "..."


class TestingAnalyzer(Analyzer):
    """Check for missing tests, missing runner configuration, and missing coverage setup."""

    def __init__(self) -> None:
        self._message: str | None = None

    @property
    def name(self) -> str:
        return "testing-hygiene"

    def is_applicable(self, context: RepositoryContext) -> bool:
        return bool(context.detected_languages)

    def completion_message(self) -> str | None:
        return self._message

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        self._reset_reporting()
        self._message = None
        candidates = self._candidate_files(context)
        if not candidates:
            self._message = "No source or test files were eligible for testing-hygiene checks."
            return []

        python_sources = [f for f in candidates if _suffix(f.path) in _PYTHON_SUFFIXES]
        jsts_sources = [f for f in candidates if _suffix(f.path) in _JS_TS_SUFFIXES]
        python_tests = [f for f in python_sources if _is_test_path(f.path)]
        jsts_tests = [f for f in jsts_sources if _is_test_path(f.path)]
        python_code = [f for f in python_sources if f not in python_tests]
        jsts_code = [f for f in jsts_sources if f not in jsts_tests]

        inventory = build_dependency_inventory(context)
        declared_python = {dep.key for dep in inventory.declared_for(Ecosystem.PYPI)}
        declared_npm = {dep.key for dep in inventory.declared_for(Ecosystem.NPM)}

        findings: list[Finding] = []
        findings.extend(
            self._missing_tests(
                context,
                language=DetectedLanguage.PYTHON,
                source_files=python_code,
                test_files=python_tests,
                rule_id="RL-TEST-001",
                manifest_hint="Add a `tests/` directory with `test_*.py` files.",
            )
        )
        findings.extend(
            self._missing_tests(
                context,
                language=DetectedLanguage.TYPESCRIPT
                if DetectedLanguage.TYPESCRIPT in context.detected_languages
                else DetectedLanguage.JAVASCRIPT,
                source_files=jsts_code,
                test_files=jsts_tests,
                rule_id="RL-TEST-002",
                manifest_hint="Add `*.test.ts`/`*.spec.ts` files next to the sources.",
            )
        )

        findings.extend(
            self._check_runner_configuration(
                context,
                python_tests=python_tests,
                jsts_tests=jsts_tests,
                declared_python=declared_python,
                declared_npm=declared_npm,
                inventory=inventory,
            )
        )
        findings.extend(
            self._check_coverage_configuration(
                context,
                has_tests=bool(python_tests or jsts_tests),
                declared_python=declared_python,
                declared_npm=declared_npm,
                inventory=inventory,
            )
        )
        findings.extend(
            self._check_undeclared_pytest(
                context,
                python_tests=python_tests,
                declared_python=declared_python,
                inventory=inventory,
            )
        )

        self._message = (
            f"Found {len(python_tests)} Python and {len(jsts_tests)} JavaScript/TypeScript "
            "test file(s)."
        )
        return self._limit_findings(findings, config.max_findings_per_analyzer)

    def _candidate_files(self, context: RepositoryContext) -> list[DiscoveredFile]:
        selected: list[DiscoveredFile] = []
        for item in context.files:
            if not _eligible(context, item):
                continue
            suffix = _suffix(item.path)
            if suffix in _PYTHON_SUFFIXES or suffix in _JS_TS_SUFFIXES:
                selected.append(item)
        return selected

    def _missing_tests(
        self,
        context: RepositoryContext,
        *,
        language: DetectedLanguage,
        source_files: list[DiscoveredFile],
        test_files: list[DiscoveredFile],
        rule_id: str,
        manifest_hint: str,
    ) -> list[Finding]:
        if test_files or not source_files:
            return []

        ecosystem = "Python" if language is DetectedLanguage.PYTHON else "JavaScript/TypeScript"
        return [
            Finding(
                rule_id=rule_id,
                category=Category.TESTING,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title=f"No {ecosystem} tests found in the repository",
                evidence=(
                    f"Found {len(source_files)} {ecosystem} source file(s) but no recognizable "
                    "test files or test directories."
                ),
                explanation=(
                    "Without automated tests, regressions are only discovered by users, and "
                    "there is no repeatable way to verify changes."
                ),
                recommendation=f"{manifest_hint} Start with the highest-risk modules.",
                verification="Confirm the test command discovers at least one test case.",
                source=_SOURCE,
            )
        ]

    def _check_runner_configuration(
        self,
        context: RepositoryContext,
        *,
        python_tests: list[DiscoveredFile],
        jsts_tests: list[DiscoveredFile],
        declared_python: set[str],
        declared_npm: set[str],
        inventory: DependencyInventory,
    ) -> list[Finding]:
        findings: list[Finding] = []
        names = {
            PurePosixPath(item.path).name for item in context.files if _eligible(context, item)
        }

        python_runner = (
            self._python_runner_configured(context, declared_python, names)
            if python_tests
            else True
        )
        if (
            python_tests
            and python_runner is not True
            and (python_runner is None or not inventory.declarations_complete(Ecosystem.PYPI))
        ):
            self._mark_reporting_failure(
                "Python test runner configuration or dependency declarations could not be verified."
            )
        elif python_tests and python_runner is False:
            findings.append(
                Finding(
                    rule_id="RL-TEST-003",
                    category=Category.TESTING,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title="Python tests exist but no test runner is configured",
                    location=FindingLocation(path=python_tests[0].path),
                    evidence=(
                        "Test files were found, but no pytest/tox/nox configuration or declared "
                        "test runner dependency was detected."
                    ),
                    explanation=(
                        "Tests without a declared runner or configuration are easy to skip in "
                        "CI because the execution command is undocumented and unverified."
                    ),
                    recommendation=(
                        "Add `[tool.pytest.ini_options]` to pyproject.toml (or a pytest.ini) and "
                        "declare pytest in a development dependency group."
                    ),
                    verification="Run the declared test command in a clean environment.",
                    source=_SOURCE,
                )
            )

        jsts_runner = (
            self._jsts_runner_configured(context, declared_npm, names) if jsts_tests else True
        )
        if (
            jsts_tests
            and jsts_runner is not True
            and (jsts_runner is None or not inventory.declarations_complete(Ecosystem.NPM))
        ):
            self._mark_reporting_failure(
                "JavaScript test runner configuration or dependency declarations could not be "
                "verified."
            )
        elif jsts_tests and jsts_runner is False:
            findings.append(
                Finding(
                    rule_id="RL-TEST-003",
                    category=Category.TESTING,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title="JavaScript/TypeScript tests exist but no test script is configured",
                    location=FindingLocation(path=jsts_tests[0].path),
                    evidence=(
                        "Test files were found, but package.json declares no `test` script, no "
                        "recognized runner dependency, and no runner config file."
                    ),
                    explanation=(
                        "A missing `test` script means CI systems and contributors have no "
                        "standard way to execute the test suite."
                    ),
                    recommendation=(
                        'Add a `"test"` script to package.json (for example `vitest run`) and '
                        "declare the runner in devDependencies."
                    ),
                    verification="Run `npm test` in a clean checkout.",
                    source=_SOURCE,
                )
            )
        return findings

    @staticmethod
    def _python_runner_configured(
        context: RepositoryContext, declared_python: set[str], names: set[str]
    ) -> bool | None:
        if declared_python & _PYTHON_RUNNERS or names & _PYTHON_RUNNER_FILES:
            return True
        unknown = False
        pyproject = context.files_by_path.get("pyproject.toml")
        if pyproject is not None and _eligible(context, pyproject):
            text = _safe_text(context, pyproject.path)
            if text is None:
                unknown = True
            else:
                try:
                    data = tomllib.loads(text)
                except tomllib.TOMLDecodeError:
                    unknown = True
                else:
                    tool = _as_mapping(data.get("tool"))
                    if "pytest" in tool or "tox" in tool or "nox" in tool:
                        return True
        setup_cfg = context.files_by_path.get("setup.cfg")
        if setup_cfg is not None and _eligible(context, setup_cfg):
            text = _safe_text(context, setup_cfg.path)
            if text is None:
                unknown = True
            elif "[tool:pytest]" in text:
                return True
        return None if unknown else False

    @staticmethod
    def _jsts_runner_configured(
        context: RepositoryContext, declared_npm: set[str], names: set[str]
    ) -> bool | None:
        if declared_npm & _JS_RUNNERS:
            return True
        if any(name.startswith(_JS_RUNNER_FILE_PREFIXES) for name in names):
            return True

        package_json = context.files_by_path.get("package.json")
        if package_json is None or not _eligible(context, package_json):
            return False
        text = _safe_text(context, package_json.path)
        if text is None:
            return None
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            return None
        if not isinstance(data, dict):
            return None
        scripts = _as_mapping(cast("dict[str, Any]", data).get("scripts"))
        test_script = scripts.get("test")
        if not isinstance(test_script, str):
            return False
        placeholder_scripts = {
            'echo "Error: no test specified" && exit 1',
            "exit 1",
        }
        return bool(test_script.strip()) and test_script.strip() not in placeholder_scripts

    def _check_coverage_configuration(
        self,
        context: RepositoryContext,
        *,
        has_tests: bool,
        declared_python: set[str],
        declared_npm: set[str],
        inventory: DependencyInventory,
    ) -> list[Finding]:
        if not has_tests:
            return []
        declared_coverage = (declared_python | declared_npm) & _COVERAGE_TOOLS
        unknown_declarations = not (
            inventory.declarations_complete(Ecosystem.PYPI)
            and inventory.declarations_complete(Ecosystem.NPM)
        )
        if not declared_coverage and not unknown_declarations:
            return []
        configured = self._coverage_configured(context)
        if configured is True:
            return []
        if not declared_coverage or configured is None:
            self._mark_reporting_failure("Coverage tooling or configuration could not be verified.")
            return []

        tools = ", ".join(sorted(declared_coverage))
        return [
            Finding(
                rule_id="RL-TEST-004",
                category=Category.TESTING,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="Coverage tooling is declared but not configured",
                evidence=f"Declared coverage dependency/dependencies: {tools}.",
                explanation=(
                    "Coverage tooling without configuration is usually not collected in CI, "
                    "so coverage regressions go unnoticed."
                ),
                recommendation=(
                    "Add coverage configuration (`[tool.coverage.*]` or `.coveragerc` for "
                    "Python, `coverage` settings for vitest/jest) and report coverage in CI."
                ),
                verification="Run the test suite with coverage enabled and inspect the report.",
                source=_SOURCE,
            )
        ]

    @staticmethod
    def _coverage_configured(context: RepositoryContext) -> bool | None:
        names = {
            PurePosixPath(item.path).name for item in context.files if _eligible(context, item)
        }
        if names & _COVERAGE_FILE_NAMES:
            return True
        unknown = False
        pyproject = context.files_by_path.get("pyproject.toml")
        if pyproject is not None and _eligible(context, pyproject):
            text = _safe_text(context, pyproject.path)
            if text is None:
                unknown = True
            else:
                try:
                    data = tomllib.loads(text)
                except tomllib.TOMLDecodeError:
                    unknown = True
                else:
                    if "coverage" in _as_mapping(data.get("tool")):
                        return True
        for name in ("vitest.config.ts", "vitest.config.js", "vite.config.ts", "vite.config.js"):
            item = context.files_by_path.get(name)
            if item is None or not _eligible(context, item):
                continue
            text = _safe_text(context, name)
            if text is None:
                unknown = True
            elif "coverage" in text:
                return True
        return None if unknown else False

    def _check_undeclared_pytest(
        self,
        context: RepositoryContext,
        *,
        python_tests: list[DiscoveredFile],
        declared_python: set[str],
        inventory: DependencyInventory,
    ) -> list[Finding]:
        if not python_tests or "pytest" in declared_python:
            return []

        incomplete_sample = len(python_tests) > _MAX_TEST_FILES_READ
        for item in python_tests[:_MAX_TEST_FILES_READ]:
            try:
                text, truncated = context.read_text_prefix(item.path, _MAX_TEST_BYTES)
            except (DiscoveryError, OversizedFileAccessError, SensitiveFileAccessError, OSError):
                incomplete_sample = True
                continue
            match = re.search(r"^\s*(?:import pytest\b|from pytest\b)", text, re.MULTILINE)
            # A match ending at a truncated boundary may continue as a longer identifier.
            witness = match is not None and (not truncated or match.end() < len(text))
            if not witness:
                incomplete_sample |= truncated
                continue
            if not inventory.declarations_complete(Ecosystem.PYPI):
                self._mark_reporting_failure(
                    "pytest was imported, but incomplete dependency declarations prevent "
                    "verification of whether it is declared."
                )
                return []
            return [
                Finding(
                    rule_id="RL-TEST-005",
                    category=Category.TESTING,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title="pytest is imported by tests but not declared as a dependency",
                    location=FindingLocation(path=item.path),
                    evidence=f"`{item.path}` imports pytest, but no manifest declares it.",
                    explanation=(
                        "Tests that rely on an undeclared dependency fail in clean environments "
                        "and cannot be installed reproducibly."
                    ),
                    recommendation=(
                        "Declare pytest in a development dependency group (for example "
                        "`[dependency-groups]` or `project.optional-dependencies.dev`)."
                    ),
                    verification=(
                        "Create a clean virtual environment and install only declared dependencies."
                    ),
                    source=_SOURCE,
                )
            ]
        if incomplete_sample:
            self._mark_reporting_failure(
                "Python test files or their byte-bounded contents could not all be checked "
                "for pytest imports."
            )
        return []


__all__ = ["TestingAnalyzer"]
