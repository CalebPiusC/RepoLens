"""Shared pytest fixtures for synthetic repository generation."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest


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
    ) -> Path:
        root = tmp_path / name
        root.mkdir(parents=True, exist_ok=True)

        if include_license:
            (root / "LICENSE").write_text(
                "MIT License\nCopyright (c) 2026 Test\n", encoding="utf-8"
            )
        if include_readme:
            (root / "README.md").write_text(
                "# Sample Python Repo\n\nA healthy test repository.\n",
                encoding="utf-8",
            )
        if include_gitignore:
            (root / ".gitignore").write_text(
                "__pycache__/\n*.py[codz]\n.venv/\n.env\ndist/\n",
                encoding="utf-8",
            )
        if include_pyproject:
            (root / "pyproject.toml").write_text(
                '[project]\nname = "sample"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n',
                encoding="utf-8",
            )

        pkg = root / "src" / "sample"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "__init__.py").write_text('"""Sample package."""\n', encoding="utf-8")
        (pkg / "core.py").write_text(
            "def add(a: int, b: int) -> int:\n    return a + b\n",
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
            '{\n  "name": "sample-ts",\n  "version": "1.0.0",\n'
            '  "devDependencies": {\n    "typescript": "^5.6.0"\n  }\n}\n',
            encoding="utf-8",
        )
        (root / "tsconfig.json").write_text(
            '{\n  "compilerOptions": {\n    "strict": true\n  }\n}\n',
            encoding="utf-8",
        )
        if include_lockfile:
            (root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")

        src = root / "src"
        src.mkdir(parents=True, exist_ok=True)
        (src / "index.ts").write_text(
            "export const greet = (name: string): string => `Hello, ${name}`;\n",
            encoding="utf-8",
        )
        return root

    return _create
