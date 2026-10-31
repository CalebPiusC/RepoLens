"""Integration tests for the packaged ``repolens`` console entry point.

These tests execute the installed executable (or ``python -m repolens``) in a subprocess
so packaging, entry-point registration, and real exit codes are exercised end to end.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import sysconfig
from collections.abc import Callable
from pathlib import Path

import pytest

from repolens import SCHEMA_VERSION, __version__

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"


def _cli_argv() -> list[str]:
    """Prefer the installed console script; fall back to ``python -m repolens``."""
    executable = "repolens.exe" if sys.platform == "win32" else "repolens"
    candidate = Path(sysconfig.get_path("scripts")) / executable
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
    # Windows process launchers and temporary directories need these OS variables, even
    # though the test deliberately does not inherit arbitrary user configuration.
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT"):
            if key in os.environ:
                env[key] = os.environ[key]
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


def test_entry_point_json_output_is_machine_readable(
    make_python_repo: Callable[..., Path], packaged_cli_available: bool
) -> None:
    """End-to-end: stdout must parse as one document and agree with the exit status."""
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    repo = make_python_repo(include_license=False)  # one MEDIUM finding

    result = _run(["scan", str(repo), "--format", "json"])

    assert result.returncode == 1, result.stderr
    assert result.stderr == ""
    document = json.loads(result.stdout)
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["repository_name"] == repo.name
    assert document["result"]["exit_code"] == result.returncode
    assert document["result"]["status"] == "findings"
    assert [finding["rule_id"] for finding in document["findings"]] == ["RL-STRUCT-001"]
    assert "\\x1b[" not in result.stdout
    # The human-readable report must not leak into the JSON stream.
    assert "Summary" not in result.stdout
    assert "RepoLens 0.1.0" not in result.stdout


def test_entry_point_json_output_keeps_errors_off_stdout(
    tmp_path: Path, packaged_cli_available: bool
) -> None:
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")

    result = _run(["scan", str(tmp_path / "missing"), "--format", "json"])

    assert result.returncode == 2
    assert result.stdout == ""
    assert "error:" in result.stderr


def test_entry_point_json_output_is_deterministic_across_runs(
    make_python_repo: Callable[..., Path], packaged_cli_available: bool
) -> None:
    """Two scans of identical content differ only in the timestamp and the duration."""
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    repo = make_python_repo()

    first = json.loads(_run(["scan", str(repo), "--format", "json"]).stdout)
    second = json.loads(_run(["scan", str(repo), "--format", "json"]).stdout)

    volatile = ("scanned_at", "duration_ms")
    for document in (first, second):
        for key in volatile:
            del document[key]
        for outcome in document["analyzer_outcomes"]:
            del outcome["duration_ms"]

    assert first == second


def test_entry_point_writes_a_self_contained_html_report(
    make_python_repo: Callable[..., Path], tmp_path: Path, packaged_cli_available: bool
) -> None:
    """End-to-end: `--format html --output` writes one offline-ready document."""
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    repo = make_python_repo(include_license=False)  # one MEDIUM finding
    destination = tmp_path / "report.html"

    result = _run(["scan", str(repo), "--format", "html", "--output", str(destination)])

    assert result.returncode == 1, result.stderr
    assert result.stdout == ""
    document = destination.read_text(encoding="utf-8")
    assert document.startswith("<!DOCTYPE html>")
    assert document.rstrip().endswith("</html>")
    assert "RL-STRUCT-001" in document
    assert repo.name in document
    assert "<script" not in document.lower()
    assert "http://" not in document
    assert "https://" not in document


def test_entry_point_html_report_matches_the_json_verdict(
    make_python_repo: Callable[..., Path], packaged_cli_available: bool
) -> None:
    """The HTML report and the JSON document must never disagree about the outcome."""
    if not packaged_cli_available:  # pragma: no cover - environment dependent
        pytest.skip("repolens console script is not installed in this environment")
    repo = make_python_repo(include_license=False)

    html_run = _run(["scan", str(repo), "--format", "html"])
    json_document = json.loads(_run(["scan", str(repo), "--format", "json"]).stdout)

    assert html_run.returncode == json_document["result"]["exit_code"]
    assert json_document["result"]["status"] == "findings"
    assert "Findings detected" in html_run.stdout
    for finding in json_document["findings"]:
        assert finding["rule_id"] in html_run.stdout
