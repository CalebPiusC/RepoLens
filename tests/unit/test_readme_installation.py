"""Guard the installation and first-run documentation against drift.

These assertions are deliberately coarse: they pin the *facts* that were verified against a
clean installation (install from the GitHub URL, no PyPI distribution, the quick-start commands,
and a troubleshooting section), not the prose around them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from repolens import __version__

_README = Path(__file__).resolve().parents[2] / "README.md"


def _readme() -> str:
    return _README.read_text(encoding="utf-8")


def _section(heading: str) -> str:
    """Return the README section at ``heading`` up to the next peer heading.

    Fenced code blocks are skipped while looking for the boundary, because a shell or
    console transcript can contain lines that start with ``#`` (a comment, or the
    ``# repolens: wrote ...`` confirmation) which are not markdown headings.
    """
    readme = _readme()
    start = readme.index(heading)
    level = len(heading) - len(heading.lstrip("#"))
    marker = re.compile(rf"^(#{{1,{level}}}) ")
    in_fence = False
    offset = start + len(heading)
    for line in readme[start + len(heading) :].splitlines(keepends=True):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        elif not in_fence and marker.match(line):
            return " ".join(readme[start:offset].split())
        offset += len(line)
    return " ".join(readme[start:].split())


def test_readme_documents_source_installs_and_pins() -> None:
    section = _section("## Installation")
    base = "https://github.com/CalebPiusC/RepoLens"

    assert f"{base}/archive/refs/heads/main.zip" in section
    assert f"{base}/archive/<full-commit-sha>.zip" in section
    assert f"git+{base}.git@<full-commit-sha>" in section
    assert f"repolens[tools] @ {base}/archive/refs/heads/main.zip" in section
    assert "does **not** lock transitive dependency versions" in section


def test_readme_never_claims_repolens_is_on_pypi() -> None:
    section = _section("### PyPI")

    assert "not published to PyPI" in section
    assert "No matching distribution found for repolens" in section
    assert "intended future command" in section
    assert "currently fails" in section


def test_readme_version_example_matches_the_package() -> None:
    match = re.search(r"(?m)^\$ repolens --version\nrepolens (\S+)$", _readme())
    assert match is not None
    assert match.group(1) == __version__


def test_platform_install_commands_are_separate() -> None:
    linux = _section("### Linux and macOS")
    windows = _section("### Windows (PowerShell)")

    assert 'python3 -m venv "$HOME/.venvs/repolens"' in linux
    assert '. "$HOME/.venvs/repolens/bin/activate"' in linux
    assert 'py -3 -m venv "$HOME\\.venvs\\repolens"' in windows
    assert 'Scripts\\Activate.ps1"' in windows
    assert "Scripts\\repolens.exe" in windows
    for section in (linux, windows):
        assert "python -m pip install" in section
        assert "python -m pip check" in section
        assert "repolens --version" in section
        assert "repolens scan ." in section


def test_upgrade_uninstall_and_development_installation() -> None:
    lifecycle = _section("### Upgrading and uninstalling")
    development = _section("### Development installation")

    assert "not available yet" in lifecycle
    assert "--force-reinstall" in lifecycle
    assert "same package version" in lifecycle
    assert "python -m pip uninstall repolens" in lifecycle
    assert "shared dependencies" in lifecycle
    assert 'python -m pip install -e ".[dev]"' in development
    assert "docs/contributing/README.md" in development


@pytest.mark.parametrize(
    "command",
    [
        "repolens scan .",
        "repolens scan . --format json",
        "repolens scan . --format html > report.html",
        "repolens scan . --format html --output report.html",
        "repolens scan --help",
        "repolens --help",
    ],
)
def test_quick_start_documents_the_verified_commands(command: str) -> None:
    section = _section("## Quick start")

    assert command in section


def test_quick_start_explains_viewing_the_report_and_exit_codes() -> None:
    section = _section("## Quick start")

    for viewer in ("start report.html", "open report.html", "xdg-open report.html"):
        assert viewer in section
    assert "Only `0` means" in section


def test_troubleshooting_covers_the_documented_failure_modes() -> None:
    section = _section("## Troubleshooting")

    for topic in (
        "### The `repolens` command is not recognized",
        "### Ruff or Bandit is reported as `unavailable` even though it is installed",
        "### Python or pip is not available",
        "### Git is not found during installation",
        "### Installation fails because of the Python version",
        "### The scan reports findings from unrelated code",
    ):
        assert topic in section


def test_troubleshooting_python_version_advice_matches_the_metadata() -> None:
    """The version floor quoted in the README must match the packaged requirement."""
    pyproject = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    requires_python = re.search(r'requires-python = "([^"]+)"', pyproject)

    assert requires_python is not None
    assert requires_python.group(1) == ">=3.11"
    assert "Requires-Python: >=3.11" in _section("## Troubleshooting")


def test_html_section_documents_viewing_the_file() -> None:
    section = _section("## HTML report")

    assert "#### Viewing the report" in section
    assert "No web server, network connection, or JavaScript is needed" in section
    assert "relative to the directory you run the command in" in section
