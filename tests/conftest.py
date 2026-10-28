"""Shared pytest fixtures for synthetic repository generation."""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import sys
import tempfile
import textwrap
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
        base_dir: Path | None = None,
    ) -> Path:
        root = (base_dir or tmp_path) / name
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


_STUB_PREAMBLE = """\
import json
import os
import sys
import time
from pathlib import Path

_args = sys.argv[1:]


def emit(payload: object) -> None:
    \"\"\"Write ``payload`` as one JSON document, like a real analyzer does.\"\"\"
    print(json.dumps(payload))


def append_args(path: str) -> None:
    \"\"\"Append every received argument to ``path``, one per line, unmodified.\"\"\"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\\n".join(_args) + "\\n")
"""


def _write_tool_launcher(bin_dir: Path, name: str, implementation: Path) -> Path:
    """Create a launcher named ``name`` that runs ``implementation`` with ``sys.executable``.

    Windows resolves executables through ``PATHEXT`` and has no shebang support, so the
    stub is a ``.cmd`` wrapper there and a POSIX shell wrapper elsewhere. Both forward the
    arguments verbatim, which keeps the argument-passing tests meaningful on every platform.
    """
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI only
        launcher = bin_dir / f"{name}.cmd"
        launcher.write_text(
            f'@echo off\r\n"{sys.executable}" "{implementation}" %*\r\n',
            encoding="utf-8",
        )
        return launcher

    launcher = bin_dir / name
    launcher.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(implementation))} "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return launcher


@pytest.fixture
def install_fake_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Path]:
    """Install a stub executable on a temporary PATH and invalidate probe caches.

    The stub lets tests exercise the real subprocess execution path without requiring
    Ruff, Bandit, or Biome to be installed on the test machine. ``script`` is Python source
    executed by the stub launcher, so the same stub runs on POSIX and Windows; it may use
    the ``_args`` argument list and the ``emit``/``append_args`` helpers.
    """

    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    def _install(name: str, script: str, *, version: str | None = None) -> Path:
        version_guard = (
            f"_VERSION = {version!r}\n"
            'if _VERSION is not None and _args[:1] == ["--version"]:\n'
            "    print(_VERSION)\n"
            "    raise SystemExit(0)\n"
            if version is not None
            else ""
        )
        implementation = bin_dir / f"{name}-stub.py"
        implementation.write_text(
            f"{_STUB_PREAMBLE}\n{version_guard}{textwrap.dedent(script).strip()}\n",
            encoding="utf-8",
        )
        launcher = _write_tool_launcher(bin_dir, name, implementation)
        current = os.environ.get("PATH", "")
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{current}")
        clear_tool_cache()
        return launcher

    return _install


@pytest.fixture
def make_symlink() -> Callable[..., Path]:
    """Create a symbolic link, skipping the test where the OS forbids unprivileged links.

    An unprivileged Windows account can only create symbolic links when Developer Mode is
    enabled, so the symlink-boundary tests are skipped there instead of failing.
    """

    def _create(link: Path, target: Path, *, target_is_directory: bool = False) -> Path:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (OSError, NotImplementedError) as exc:  # pragma: no cover - platform dependent
            pytest.skip(f"this environment cannot create symbolic links: {exc}")
        return link

    return _create


@pytest.fixture
def short_root() -> Iterator[Path]:
    """Yield a scratch repository root whose absolute path is deliberately short.

    Windows enforces a ~260 character path limit when long-path support is disabled. Nesting
    dozens of directories below pytest's own (long) ``tmp_path`` would hit that limit before
    the discovery depth limit is reached, so depth tests start from the system temp directory.
    """
    raw = Path(tempfile.mkdtemp(prefix="rl-"))
    try:
        yield raw
    finally:
        shutil.rmtree(raw, ignore_errors=True)


@pytest.fixture
def make_nested_directories() -> Callable[..., Path]:
    """Nest one-character directories below ``root``, skipping if the OS refuses.

    Reusing a single-character name keeps the absolute path short enough for filesystems
    without long-path support; uniqueness is only required between siblings.
    """

    def _create(root: Path, depth: int, *, leaf: Sequence[str] = ()) -> Path:
        current = root
        try:
            for _ in range(depth):
                current = current / "d"
                current.mkdir(parents=True, exist_ok=True)
            for name in leaf:
                current = current / name
                current.mkdir()
        except OSError as exc:  # pragma: no cover - platform dependent
            pytest.skip(f"the filesystem cannot represent {depth} nested directories: {exc}")
        return current

    return _create


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
        skipped_by_depth_count: int = 0,
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
                skipped_by_depth_count=skipped_by_depth_count,
                detected_languages=[],
            ),
            analyzer_outcomes=analyzer_outcomes,
            findings=list(findings),
        )

    return _create
