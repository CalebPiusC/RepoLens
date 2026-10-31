"""Keep the package version and installation metadata tied to one source."""

from __future__ import annotations

import importlib.metadata
import tomllib
from pathlib import Path

from packaging.version import Version

from repolens import __version__

_ROOT = Path(__file__).resolve().parents[2]


def test_hatch_and_runtime_share_a_static_version_source() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    metadata = project["project"]
    assert "version" not in metadata
    assert "version" in metadata["dynamic"]
    assert project["tool"]["hatch"]["version"]["path"] == "src/repolens/_version.py"
    assert str(Version(__version__)) == __version__
    assert importlib.metadata.version("repolens") == __version__


def test_project_urls_and_console_script_are_declared() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == "repolens"
    assert project["scripts"]["repolens"] == "repolens.cli:main"
    assert project["urls"]["Repository"] == "https://github.com/CalebPiusC/RepoLens"
    assert project["urls"]["Issues"] == "https://github.com/CalebPiusC/RepoLens/issues"
    assert project["requires-python"] == ">=3.11"
