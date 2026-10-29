"""Guard the installation and first-run documentation against drift.

These assertions are deliberately coarse: they pin the *facts* that were verified against a
clean installation (install from the GitHub URL, no PyPI distribution, the quick-start commands,
and a troubleshooting section), not the prose around them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

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


def test_readme_documents_installing_from_the_github_url() -> None:
    """The supported install method must be documented as a URL, not only as a clone."""
    section = _section("## Installation")

    assert 'pip install "git+https://github.com/CalebPiusC/RepoLens.git"' in section
    # A pinned form must be offered for reproducible installs.
    assert "@<commit-sha>" in section
    # The `tools` extra must be installable without a checkout.
    assert "repolens[tools] @ git+https://github.com/CalebPiusC/RepoLens.git" in section


def test_readme_never_claims_repolens_is_on_pypi() -> None:
    """`pip install repolens` fails; the README must say so instead of recommending it."""
    section = _section("### PyPI")

    assert "not published to PyPI" in section
    assert "No matching distribution found for repolens" in section
    # Any bare `pip install repolens` may only appear as the expected failure.
    for line in _readme().splitlines():
        if "pip install repolens" in line:
            assert "fails" in line or "ERROR" in line, line


def test_readme_keeps_development_installation_separate() -> None:
    section = _section("### Development installation")

    assert 'pip install -e ".[dev]"' in section
    assert "docs/contributing/README.md" in section


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
