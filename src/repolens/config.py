"""Scan configuration, resource budgets, and default exclusion rules."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".hypothesis",
        ".venv",
        "venv",
        "env",
        "node_modules",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".turbo",
        ".parcel-cache",
        "dist",
        "build",
        "out",
        "target",
        "htmlcov",
        "coverage",
    }
)

# Subset of excluded directories that represent vendor/virtualenv/bytecode artifacts
# which should be covered by .gitignore if present inside a repository workspace.
HYGIENE_TRACKED_ARTIFACT_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
    }
)


class ScanConfig(BaseModel):
    """Runtime limits and behavioral settings for a RepoLens scan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_files: int = Field(default=10_000, ge=1, le=500_000)
    max_file_size_bytes: int = Field(default=1_048_576, ge=1_024, le=52_428_800)
    max_total_bytes: int = Field(default=52_428_800, ge=4_096, le=1_073_741_824)
    max_evidence_chars: int = Field(default=500, ge=64, le=4_000)
    subprocess_timeout_seconds: float = Field(default=30.0, gt=0.1, le=300.0)
    subprocess_max_output_bytes: int = Field(default=5_242_880, ge=4_096, le=52_428_800)
    excluded_dirs: frozenset[str] = Field(default=DEFAULT_EXCLUDED_DIRS)
    reject_symlink_root: bool = True
    fail_fast: bool = False
