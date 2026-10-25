"""Shared pytest fixtures for synthetic repository generation."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from repolens.analyzers.tooling import clear_tool_cache
from repolens.models import (
    AnalyzerOutcome,
    AnalyzerStatus,
    Category,
    DiscoverySummary,
    Finding,
    FindingLocation,
    FindingSource,
    ScanReport,
    Severity,
    SourceKind,
)


@pytest.fixture(autouse=True)
def _clear_tool_availability_cache() -> Iterator[None]:
    """Prevent cached external-tool probes from leaking between tests."""
    clear_tool_cache()
    yield
    clear_tool_cache()


@pytest.fixture
def make_python_repo(tmp_path: Path) -> Callable[..., Path]:
    """Create a minimal, healthy Python repository inside a temporary directory."""

    def _create(
        name: str = "sample-py-repo",
        *,
        include_license: bool = True,
        include_readme: bool = True,
        include_gitignore: bool = True,
        include_pyproject: bool = True,
        include_tests: bool = True,
    ) -> Path:
        root = tmp_path / name
        root.mkdir(parents=True, exist_ok=True)

        if include_license:
            (root / "LICENSE").write_text(
                "MIT License\nCopyright (c) 2026 Test\n", encoding="utf-8"
            )
        if include_readme:
            (root / "README.md").write_text(
                "# Sample Python Repo\n\nA healthy test repository.\n", encoding="utf-8"
            )
        if include_gitignore:
            (root / ".gitignore").write_text(
                "__pycache__/\n*.py[codz]\n.venv/\n.env\ndist/\n",
                encoding="utf-8",
            )
        if include_pyproject:
            (root / "pyproject.toml").write_text(
                '[project]\nname = "sample"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
                '\n[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
                encoding="utf-8",
            )

        pkg = root / "src" / "sample"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "__init__.py").write_text('"""Sample package."""\n', encoding="utf-8")
        (pkg / "core.py").write_text(
            "def add(a: int, b: int) -> int:\n    return a + b\n",
            encoding="utf-8",
        )

        if include_tests:
            tests_dir = root / "tests"
            tests_dir.mkdir(parents=True, exist_ok=True)
            (tests_dir / "test_core.py").write_text(
                "from sample.core import add\n\n\n"
                "def test_add() -> None:\n    assert add(1, 2) == 3\n",
                encoding="utf-8",
            )
        return root

    return _create


@pytest.fixture
def make_jsts_repo(tmp_path: Path) -> Callable[..., Path]:
    """Create a minimal, healthy TypeScript repository inside a temporary directory."""

    def _create(
        name: str = "sample-ts-repo",
        *,
        include_gitignore: bool = True,
        include_lockfile: bool = True,
        include_tests: bool = True,
    ) -> Path:
        root = tmp_path / name
        root.mkdir(parents=True, exist_ok=True)
        (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
        (root / "README.md").write_text(
            "# Sample TS Repo\n\nTypeScript library.\n", encoding="utf-8"
        )

        if include_gitignore:
            (root / ".gitignore").write_text("node_modules/\ndist/\n.env\n", encoding="utf-8")

        (root / "package.json").write_text(
            '{\n  "name": "sample-ts",\n  "version": "1.0.0",\n  "license": "MIT",\n'
            '  "scripts": {\n    "test": "vitest run"\n  },\n'
            '  "devDependencies": {\n    "typescript": "^5.6.0",\n    "vitest": "^2.1.0"\n  }\n}\n',
            encoding="utf-8",
        )
        (root / "tsconfig.json").write_text(
            '{\n  "compilerOptions": {\n    "strict": true\n  }\n}\n', encoding="utf-8"
        )
        if include_lockfile:
            (root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")

        src = root / "src"
        src.mkdir(parents=True, exist_ok=True)
        (src / "index.ts").write_text(
            "export const greet = (name: string): string => `Hello, ${name}`;\n",
            encoding="utf-8",
        )
        if include_tests:
            (src / "index.test.ts").write_text(
                'import { describe, expect, it } from "vitest";\n'
                'import { greet } from "./index";\n\n'
                'describe("greet", () => {\n'
                '  it("greets", () => {\n    expect(greet("x")).toBe("Hello, x");\n  });\n});\n',
                encoding="utf-8",
            )
        return root

    return _create


@pytest.fixture
def install_fake_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Path]:
    """Install a stub executable on a temporary PATH and invalidate probe caches.

    The stub lets tests exercise the real subprocess execution path without requiring
    Ruff, Bandit, or Biome to be installed on the test machine.
    """

    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    def _install(name: str, script: str) -> Path:
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{script}\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        current = os.environ.get("PATH", "")
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{current}")
        clear_tool_cache()
        return path

    return _install


@pytest.fixture
def make_finding() -> Callable[..., Finding]:
    """Build a deterministic ``Finding`` for report/CLI tests."""

    def _create(
        *,
        rule_id: str = "RL-STRUCT-001",
        severity: Severity = Severity.MEDIUM,
        category: Category = Category.STRUCTURE,
        title: str = "Missing repository LICENSE file",
        path: str | None = "LICENSE",
        start_line: int | None = None,
        tool: str = "repolens-structure",
        explanation: str = "An explicit license is required for others to use the code.",
        recommendation: str = "Add a LICENSE file at the repository root.",
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            title=title,
            location=(None if path is None else FindingLocation(path=path, start_line=start_line)),
            explanation=explanation,
            recommendation=recommendation,
            verification="Confirm the file exists at the repository root.",
            source=FindingSource(kind=SourceKind.DETERMINISTIC, tool=tool, tool_version="0.1.0"),
        )

    return _create


@pytest.fixture
def make_scan_report() -> Callable[..., ScanReport]:
    """Build a ``ScanReport`` without running any analyzer."""

    def _create(
        *,
        findings: Sequence[Finding] = (),
        outcomes: Sequence[AnalyzerOutcome] | None = None,
        repository_name: str = "sample-repo",
        truncated_by_file_limit: bool = False,
        truncated_by_byte_limit: bool = False,
        unreadable_directory_count: int = 0,
        unreadable_entry_count: int = 0,
        skipped_oversized_count: int = 0,
        skipped_symlink_count: int = 0,
        total_files: int = 5,
    ) -> ScanReport:
        analyzer_outcomes: list[AnalyzerOutcome] = list(outcomes) if outcomes is not None else []
        if outcomes is None:
            analyzer_outcomes = [
                AnalyzerOutcome(
                    analyzer_name="repolens-structure",
                    status=AnalyzerStatus.COMPLETED,
                    findings_count=len(findings),
                    duration_ms=3.0,
                )
            ]
        return ScanReport(
            repolens_version="0.1.0",
            repository_name=repository_name,
            scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
            duration_ms=12.5,
            discovery=DiscoverySummary(
                total_files_scanned=total_files,
                total_bytes_scanned=2048,
                skipped_excluded_count=0,
                skipped_symlink_count=skipped_symlink_count,
                skipped_oversized_count=skipped_oversized_count,
                sensitive_files_detected=0,
                truncated_by_file_limit=truncated_by_file_limit,
                truncated_by_byte_limit=truncated_by_byte_limit,
                unreadable_directory_count=unreadable_directory_count,
                unreadable_entry_count=unreadable_entry_count,
                detected_languages=[],
            ),
            analyzer_outcomes=analyzer_outcomes,
            findings=list(findings),
        )

    return _create
