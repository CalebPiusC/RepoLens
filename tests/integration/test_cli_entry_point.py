"""Integration tests for the packaged ``repolens`` console entry point.

These tests execute the installed executable (or ``python -m repolens``) in a subprocess
so packaging, entry-point registration, and real exit codes are exercised end to end.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from repolens import __version__

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"


def _cli_argv() -> list[str]:
    """Prefer the installed console script; fall back to ``python -m repolens``."""
    candidate = Path(sys.executable).with_name("repolens")
    if candidate.is_file():
        return [str(candidate)]
    return [sys.executable, "-m", "repolens"]


def _run(
    args: list[str], *, env_extra: dict[str, str] | None = None, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", str(Path.home())),
        "LANG": "C.UTF-8",
        "NO_COLOR": "1",
        "PYTHONPATH": os.pathsep.join(
            [str(_SRC), *([os.environ["PYTHONPATH"]] if os.environ.get("PYTHONPATH") else [])]
        ),
    }
    if env_extra:
        env.update(env_extra)
    return subprocess.run(  # fixed argv, shell-free, test-controlled
        [*_cli_argv(), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


@pytest.fixture(scope="module")
def packaged_cli_available() -> bool:
    """True when the console script (or module entry point) can be invoked."""
    result = subprocess.run(  # fixed argv, shell-free
        [*_cli_argv(), "--version"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return result.returncode == 0


def test_console_entry_point_is_declared_in_pyproject() -> None:
    pyproject = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[project.scripts]" in pyproject
    assert 'repolens = "repolens.cli:main"' in pyproject


def test_python_dash_m_entry_point_reports_version() -> None:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(_SRC),
        "NO_COLOR": "1",
    }
    result = subprocess.run(  # fixed argv, shell-free
        [sys.executable, "-m", "repolens", "--version"],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"repolens {__version__}"


def test_entry_point_help_exits_zero(packaged_cli_available: bool) -> None:
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    result = _run(["--help"])
    assert result.returncode == 0
    assert "usage: repolens" in result.stdout


def test_entry_point_scan_clean_repository(
    make_python_repo: Callable[..., Path], packaged_cli_available: bool
) -> None:
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    repo = make_python_repo()

    result = _run(["scan", str(repo), "--color", "never"])

    assert result.returncode == 0, result.stderr
    assert "No findings detected." in result.stdout
    assert "\x1b[" not in result.stdout
    assert result.stderr == ""


def test_entry_point_reports_findings_with_exit_code_one(
    make_python_repo: Callable[..., Path], packaged_cli_available: bool
) -> None:
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    repo = make_python_repo(include_license=False)

    result = _run(["scan", str(repo), "--color", "never"])

    assert result.returncode == 1
    assert "RL-STRUCT-001" in result.stdout
    assert "MEDIUM" in result.stdout
    assert "Summary" in result.stdout


def test_entry_point_invalid_path_exit_code_two(
    tmp_path: Path, packaged_cli_available: bool
) -> None:
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    result = _run(["scan", str(tmp_path / "nope")])

    assert result.returncode == 2
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""


def test_entry_point_never_executes_scanned_repository_code(
    tmp_path: Path, packaged_cli_available: bool
) -> None:
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    marker = tmp_path / "executed.marker"
    repo = tmp_path / "hostile"
    repo.mkdir()
    script = f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n"
    (repo / "setup.py").write_text(script, encoding="utf-8")
    (repo / "conftest.py").write_text(script, encoding="utf-8")
    (repo / "app.py").write_text("import os\n", encoding="utf-8")

    result = _run(["scan", str(repo), "--color", "never"])

    assert result.returncode in {0, 1}
    assert not marker.exists()


def test_entry_point_exit_code_is_usable_from_a_shell_pipeline(
    make_python_repo: Callable[..., Path], packaged_cli_available: bool
) -> None:
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    repo = make_python_repo(include_license=False)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(_SRC),
        "NO_COLOR": "1",
    }

    # A shell checks the exit status; gating on it must stop the chain on findings.
    result = subprocess.run(  # fixed argv, shell-free
        [*_cli_argv(), "scan", str(repo), "--color", "never"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        check=False,
    )
    assert result.returncode != 0
    assert "finding(s) detected" in result.stdout


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses directory permissions",
)
def test_entry_point_unreadable_directory_is_not_reported_clean(
    make_python_repo: Callable[..., Path], packaged_cli_available: bool
) -> None:
    """End-to-end regression for the false-clean scan caused by a swallowed OSError."""
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")

    # A healthy fixture that scans clean; hiding part of it must not keep it clean.
    repo = make_python_repo(include_license=False)  # one MEDIUM finding, exit 1
    assert _run(["scan", str(repo), "--min-severity", "critical"]).returncode == 0

    locked = repo / "locked"
    locked.mkdir()
    (locked / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    locked.chmod(0o000)
    try:
        try:
            list(os.scandir(locked))
        except PermissionError:
            pass
        else:  # pragma: no cover - platform dependent
            pytest.skip("this platform does not enforce directory permissions")
        result = _run(["scan", str(repo), "--min-severity", "critical", "--color", "never"])
    finally:
        locked.chmod(0o755)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "could not read 1 directory" in result.stdout
    assert "cannot be reported as clean" in result.stdout
    assert "exit code 3" in result.stdout


def test_entry_point_reports_depth_limited_scan(
    make_python_repo: Callable[..., Path],
    make_nested_directories: Callable[..., Path],
    short_root: Path,
    packaged_cli_available: bool,
) -> None:
    """A subtree beyond MAX_DIRECTORY_DEPTH must not leave the run looking clean."""
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")

    from repolens.discovery import MAX_DIRECTORY_DEPTH

    # The bare repo lives under a short root: 64 nested directories below pytest's own
    # (long) tmp_path would exceed the Windows legacy path limit.
    repo = make_python_repo(include_license=False, base_dir=short_root)  # one MEDIUM finding
    assert _run(["scan", str(repo), "--min-severity", "critical"]).returncode == 0

    deepest = make_nested_directories(repo, MAX_DIRECTORY_DEPTH, leaf=("unreachable",))
    (deepest / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    result = _run(["scan", str(repo), "--min-severity", "critical", "--color", "never"])

    assert result.returncode == 3, result.stdout + result.stderr
    assert "nested deeper than the supported limit" in result.stdout
    assert "cannot be reported as clean" in result.stdout
    assert "exit code 3" in result.stdout
