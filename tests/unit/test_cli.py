"""Unit tests for the RepoLens command-line interface."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import ClassVar

import pytest

from repolens import __version__
from repolens.analyzers.tooling import clear_tool_cache
from repolens.cli import (
    EXIT_FINDINGS,
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_OPERATIONAL,
    EXIT_USAGE,
    build_parser,
    determine_exit_code,
    main,
)
from repolens.config import ScanConfig
from repolens.exceptions import (
    DiscoveryAbortedError,
    DiscoveryError,
    SensitiveFileAccessError,
)
from repolens.models import AnalyzerOutcome, AnalyzerStatus, Finding, ScanReport, Severity


@pytest.fixture(autouse=True)
def _no_external_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Make optional tool probes deterministic: no external tools are installed."""
    empty = tmp_path / "empty-bin"
    empty.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(empty))
    clear_tool_cache()


class _FakeEngine:
    """Stand-in for ``ScanEngine`` that returns a canned result and records calls."""

    report: ClassVar[ScanReport | None] = None
    error: ClassVar[BaseException | None] = None
    calls: ClassVar[list[_FakeEngine]] = []

    def __init__(self, *, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.paths: list[Path] = []
        _FakeEngine.calls.append(self)

    def scan(self, repo_path: Path | str) -> ScanReport:
        self.paths.append(Path(repo_path))
        if _FakeEngine.error is not None:
            raise _FakeEngine.error
        assert _FakeEngine.report is not None, "test must assign a canned report"
        return _FakeEngine.report


@pytest.fixture
def fake_engine(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[_FakeEngine]]:
    """Replace the CLI's engine so tests never run real analysis."""
    _FakeEngine.report = None
    _FakeEngine.error = None
    _FakeEngine.calls = []
    monkeypatch.setattr("repolens.cli.ScanEngine", _FakeEngine)
    yield _FakeEngine
    _FakeEngine.report = None
    _FakeEngine.error = None


# --------------------------------------------------------------------------------------
# Help, version, and argument validation
# --------------------------------------------------------------------------------------


def test_version_flag_prints_version_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == EXIT_OK
    captured = capsys.readouterr()
    assert captured.out.strip() == f"repolens {__version__}"
    assert captured.err == ""


def test_top_level_help_lists_commands_and_exit_codes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--help"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "usage: repolens" in out
    assert "scan" in out
    assert "exit codes:" in out
    assert "never executes code" in out


def test_scan_help_documents_options(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--help"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "PATH" in out
    assert "--min-severity" in out
    assert "--max-findings" in out
    assert "--network-checks" in out
    assert "--color" in out
    assert "examples:" in out


def test_no_arguments_prints_help_and_flags_usage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "usage: repolens" in captured.out
    assert captured.err == ""


def test_unknown_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["frobnicate"]) == EXIT_USAGE
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.parametrize("raw_value", ["0", "-3", "abc", "10001"])
def test_invalid_max_findings_is_rejected(
    raw_value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", ".", "--max-findings", raw_value]) == EXIT_USAGE
    assert "--max-findings" in capsys.readouterr().err


def test_invalid_min_severity_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", ".", "--min-severity", "catastrophic"]) == EXIT_USAGE
    assert "invalid choice" in capsys.readouterr().err


def test_parser_defaults() -> None:
    args = build_parser().parse_args(["scan"])
    assert args.path == "."
    assert args.min_severity == "info"
    assert args.max_findings == 50
    assert args.color == "auto"
    assert args.network_checks is False


# --------------------------------------------------------------------------------------
# Engine delegation: the CLI must reuse ScanEngine rather than implement its own scanner
# --------------------------------------------------------------------------------------


def test_cli_delegates_scanning_to_engine(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "some-repo"
    target.mkdir()
    fake_engine.report = make_scan_report(findings=[make_finding()])

    assert main(["scan", str(target), "--color", "never"]) == EXIT_FINDINGS

    assert len(fake_engine.calls) == 1
    engine = fake_engine.calls[0]
    assert engine.paths == [target]
    assert isinstance(engine.config, ScanConfig)
    assert engine.config.enable_network_checks is False
    out = capsys.readouterr().out
    assert "RL-STRUCT-001" in out


def test_engine_receives_network_checks_option(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_engine.report = make_scan_report()

    assert main(["scan", ".", "--network-checks", "--color", "never"]) == EXIT_OK

    assert fake_engine.calls[0].config.enable_network_checks is True
    capsys.readouterr()


def test_engine_receives_min_severity_and_max_findings(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
    capsys: pytest.CaptureFixture[str],
) -> None:
    findings = [
        make_finding(rule_id=f"RL-RULE-{index:03d}", severity=Severity.HIGH) for index in range(3)
    ]
    fake_engine.report = make_scan_report(findings=findings)

    code = main(["scan", ".", "--min-severity", "high", "--max-findings", "1", "--color", "never"])

    assert code == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "RL-RULE-000" in out
    assert "RL-RULE-002" not in out
    assert "2 more finding(s) not shown" in out


def test_path_is_expanded_for_home_directories(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    # Windows expands ``~`` from USERPROFILE (via ntpath.expanduser), not HOME.
    monkeypatch.setenv("USERPROFILE", str(home))
    fake_engine.report = make_scan_report()

    main(["scan", "~/", "--color", "never"])

    assert fake_engine.calls[0].paths == [home]
    capsys.readouterr()


# --------------------------------------------------------------------------------------
# Exit codes
# --------------------------------------------------------------------------------------


def test_clean_scan_exits_zero(
    make_python_repo: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    repo = make_python_repo()

    assert main(["scan", str(repo), "--color", "never"]) == EXIT_OK

    out = capsys.readouterr().out
    assert "No findings detected." in out
    assert "exit code 0" in out


def test_scan_with_findings_exits_one(
    make_python_repo: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    repo = make_python_repo(include_license=False)

    assert main(["scan", str(repo), "--color", "never"]) == EXIT_FINDINGS

    out = capsys.readouterr().out
    assert "RL-STRUCT-001" in out
    assert "Missing repository LICENSE file" in out
    assert "MEDIUM" in out
    assert "exit code 1" in out


def test_severity_threshold_controls_exit_code(
    make_python_repo: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    repo = make_python_repo(include_license=False)  # medium-severity finding only

    assert main(["scan", str(repo), "--min-severity", "high", "--color", "never"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "below threshold" in out
    assert "no findings at or above 'high' severity" in out

    assert main(["scan", str(repo), "--min-severity", "medium", "--color", "never"]) == (
        EXIT_FINDINGS
    )


def test_findings_take_precedence_over_incompleteness(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(
        findings=[make_finding(severity=Severity.HIGH)],
        outcomes=[
            AnalyzerOutcome(analyzer_name="flaky", status=AnalyzerStatus.FAILED, message="boom")
        ],
    )
    assert determine_exit_code(report) == EXIT_FINDINGS
    assert determine_exit_code(make_scan_report(), Severity.CRITICAL) == EXIT_OK


def test_unavailable_analyzers_do_not_fail_a_clean_scan(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_engine.report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="ruff-python-lint",
                status=AnalyzerStatus.UNAVAILABLE,
                message="`ruff` executable was not found on PATH.",
            )
        ]
    )

    assert main(["scan", ".", "--color", "never"]) == EXIT_OK

    out = capsys.readouterr().out
    assert "unavailable" in out
    assert "optional tools are not installed" in out


@pytest.mark.parametrize("status", [AnalyzerStatus.FAILED, AnalyzerStatus.TIMED_OUT])
def test_failed_or_timed_out_analyzer_is_never_reported_as_clean(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    capsys: pytest.CaptureFixture[str],
    status: AnalyzerStatus,
) -> None:
    fake_engine.report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="bandit-python-security",
                status=status,
                message="analyzer did not finish",
            )
        ]
    )

    assert main(["scan", ".", "--color", "never"]) == EXIT_OPERATIONAL

    out = capsys.readouterr().out
    assert "scan incomplete" in out
    assert "exit code 3" in out


def test_truncated_discovery_is_never_reported_as_clean(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A resource-limit stop means part of the repository was never scanned.

    Previously this exited 0 with only a warning, which let a partial scan masquerade as
    a clean one in CI. It is now an incomplete scan (exit 3).
    """
    fake_engine.report = make_scan_report(truncated_by_file_limit=True)

    assert main(["scan", ".", "--color", "never"]) == EXIT_OPERATIONAL

    out = capsys.readouterr().out
    assert "results may be incomplete" in out
    assert "exit code 3" in out


def test_truncation_with_findings_still_exits_one(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Findings outrank incompleteness, and the output must say both."""
    fake_engine.report = make_scan_report(
        findings=[make_finding(severity=Severity.HIGH)],
        truncated_by_byte_limit=True,
    )

    assert main(["scan", ".", "--color", "never"]) == EXIT_FINDINGS

    out = capsys.readouterr().out
    assert "results may be incomplete" in out
    assert "but the scan is incomplete" in out
    assert "exit code 1" in out


def test_unreadable_directory_is_reported_and_exits_three(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Discovery that could not read part of the tree must never look clean."""
    fake_engine.report = make_scan_report(unreadable_directory_count=1)

    assert main(["scan", ".", "--color", "never"]) == EXIT_OPERATIONAL

    out = capsys.readouterr().out
    assert "could not read 1 directory" in out
    assert "cannot be reported as clean" in out
    assert "scan incomplete" in out
    assert "exit code 3" in out


def test_unreadable_entry_with_findings_exits_one(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    fake_engine.report = make_scan_report(
        findings=[make_finding(severity=Severity.CRITICAL)],
        unreadable_entry_count=2,
    )

    assert main(["scan", ".", "--color", "never"]) == EXIT_FINDINGS


def test_findings_below_threshold_with_incomplete_scan_exits_three(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Hidden findings must not mask incompleteness: nothing actionable, but not clean."""
    fake_engine.report = make_scan_report(
        findings=[make_finding(severity=Severity.LOW)],
        outcomes=[
            AnalyzerOutcome(analyzer_name="flaky", status=AnalyzerStatus.FAILED, message="boom")
        ],
    )

    assert main(["scan", ".", "--min-severity", "high", "--color", "never"]) == EXIT_OPERATIONAL

    out = capsys.readouterr().out
    assert "scan incomplete" in out
    assert "exit code 3" in out


# --------------------------------------------------------------------------------------
# Invalid input
# --------------------------------------------------------------------------------------


def test_missing_path_is_reported_without_running_analyzers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", str(tmp_path / "does-not-exist")]) == EXIT_USAGE

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err
    assert "does not exist" in captured.err
    assert "Traceback" not in captured.err


def test_scanned_file_instead_of_directory_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "file.txt"
    target.write_text("hello\n", encoding="utf-8")

    assert main(["scan", str(target)]) == EXIT_USAGE
    assert "not a directory" in capsys.readouterr().err


def test_symlinked_root_is_rejected_by_the_engine(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], make_symlink: Callable[..., Path]
) -> None:
    real = tmp_path / "real-repo"
    real.mkdir()
    link = make_symlink(tmp_path / "linked-repo", real, target_is_directory=True)

    assert main(["scan", str(link)]) == EXIT_USAGE
    assert "symbolic link" in capsys.readouterr().err


@pytest.mark.parametrize("bad_path", ["\x00", "   "])
def test_nul_and_blank_paths_are_usage_errors(
    bad_path: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", bad_path]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "error" in (captured.err + captured.out).lower()


def test_path_argument_is_not_shell_interpreted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    weird = tmp_path / "repo; rm -rf ~ $(whoami)"
    weird.mkdir()
    (weird / "README.md").write_text("# Weird\n", encoding="utf-8")

    assert main(["scan", str(weird), "--color", "never"]) in {EXIT_OK, EXIT_FINDINGS}
    assert weird.exists()
    capsys.readouterr()


# --------------------------------------------------------------------------------------
# Operational failures, interrupts, and secret safety
# --------------------------------------------------------------------------------------


def test_interrupt_returns_130(
    fake_engine: type[_FakeEngine], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_engine.error = KeyboardInterrupt()

    assert main(["scan", "."]) == EXIT_INTERRUPTED

    captured = capsys.readouterr()
    assert "interrupted" in captured.err
    assert captured.out == ""


def test_interrupt_during_rendering_returns_130(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ctrl-C must behave the same after the scan returns, not leak a traceback."""
    fake_engine.report = make_scan_report()

    def _interrupt(*args: object, **kwargs: object) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("repolens.cli.render_report", _interrupt)

    assert main(["scan", ".", "--color", "never"]) == EXIT_INTERRUPTED

    captured = capsys.readouterr()
    assert "interrupted" in captured.err
    assert "Traceback" not in captured.err


def test_mid_scan_security_abort_is_operational_not_usage(
    fake_engine: type[_FakeEngine], capsys: pytest.CaptureFixture[str]
) -> None:
    """A security abort after the walk started did not scan "nothing"; it is exit 3."""
    fake_engine.error = DiscoveryAbortedError("Entry escaped canonical root: link")

    assert main(["scan", "."]) == EXIT_OPERATIONAL

    err = capsys.readouterr().err
    assert "aborted part-way" in err
    assert "escaped canonical root" in err


def test_unexpected_error_is_reported_without_traceback_or_secrets(
    fake_engine: type[_FakeEngine], capsys: pytest.CaptureFixture[str]
) -> None:
    leaked = "ghp_" + "Z" * 32
    fake_engine.error = RuntimeError(f"unexpected failure with token {leaked}")

    assert main(["scan", "."]) == EXIT_OPERATIONAL

    captured = capsys.readouterr()
    assert leaked not in captured.err
    assert leaked not in captured.out
    assert "REDACTED" in captured.err
    assert "RuntimeError" in captured.err
    assert "Traceback" not in captured.err
    assert "report it" in captured.err


def test_repo_lens_error_maps_to_operational_failure(
    fake_engine: type[_FakeEngine], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_engine.error = SensitiveFileAccessError("refusing to read sensitive file: .env")

    assert main(["scan", "."]) == EXIT_OPERATIONAL

    err = capsys.readouterr().err
    assert "refusing to read sensitive file" in err
    assert "internal error" not in err


def test_discovery_error_maps_to_usage(
    fake_engine: type[_FakeEngine], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_engine.error = DiscoveryError("Repository path does not exist: nope")

    assert main(["scan", "nope"]) == EXIT_USAGE
    assert "does not exist" in capsys.readouterr().err


# --------------------------------------------------------------------------------------
# Safety: the CLI must not execute or install anything from the scanned repository
# --------------------------------------------------------------------------------------


def test_cli_never_executes_or_installs_scanned_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = tmp_path / "executed.marker"
    repo = tmp_path / "hostile"
    repo.mkdir()
    touch_marker = f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n"
    (repo / "setup.py").write_text(touch_marker, encoding="utf-8")
    (repo / "conftest.py").write_text(touch_marker, encoding="utf-8")
    (repo / "package.json").write_text(
        '{"name":"hostile","version":"1.0.0","scripts":{"postinstall":"touch '
        + str(marker)
        + '","test":"touch '
        + str(marker)
        + '"}}',
        encoding="utf-8",
    )
    (repo / "app.py").write_text("import os\n\nprint('hi')\n", encoding="utf-8")

    assert main(["scan", str(repo), "--color", "never"]) in {EXIT_OK, EXIT_FINDINGS}

    assert not marker.exists()
    assert not (repo / "node_modules").exists()
    assert not (repo / ".venv").exists()
    capsys.readouterr()


def test_rendered_output_never_contains_evidence_secrets(
    make_python_repo: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    repo = make_python_repo()
    secret = "ghp_" + "Q" * 32
    # `.env` is covered by the fixture's .gitignore; `.env.production` is not, so it is
    # reported as an unignored sensitive file.
    (repo / ".env.production").write_text(f"GITHUB_TOKEN={secret}\n", encoding="utf-8")

    main(["scan", str(repo), "--color", "never"])
    out = capsys.readouterr().out

    assert secret not in out
    assert "RL-SEC-001" in out


def test_scan_does_not_modify_repository(
    make_python_repo: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    repo = make_python_repo()
    before = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))

    main(["scan", str(repo), "--color", "never"])
    capsys.readouterr()

    assert sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*")) == before


def test_environment_is_not_mutated_by_scan(
    make_python_repo: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    before = dict(os.environ)

    main(["scan", str(make_python_repo()), "--color", "never"])
    capsys.readouterr()

    assert dict(os.environ) == before


# --------------------------------------------------------------------------------------
# Output controls
# --------------------------------------------------------------------------------------


def test_color_modes(
    make_python_repo: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    repo = make_python_repo(include_license=False)

    main(["scan", str(repo), "--color", "never"])
    assert "\x1b[" not in capsys.readouterr().out

    main(["scan", str(repo), "--color", "always"])
    assert "\x1b[" in capsys.readouterr().out


def test_no_color_env_suppresses_auto_colors(
    make_python_repo: Callable[..., Path],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")

    main(["scan", str(make_python_repo(include_license=False)), "--color", "auto"])

    assert "\x1b[" not in capsys.readouterr().out


def test_color_auto_disabled_for_non_tty_stream(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    # Pytest's captured stdout is not a TTY.
    from repolens.cli import _use_color

    assert _use_color("auto", sys.stdout) is False
    assert _use_color("always", sys.stdout) is True
    assert _use_color("never", sys.stdout) is False


def test_sequence_argv_is_supported() -> None:
    assert main(("--version",)) == EXIT_OK


def test_use_color_handles_stream_without_isatty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolens.cli import _use_color

    class _NoIsatty:
        def write(self, text: str) -> int:  # pragma: no cover - unused
            return len(text)

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")

    assert _use_color("auto", _NoIsatty()) is False  # type: ignore[arg-type]


def test_blank_error_message_falls_back_to_exception_type(
    fake_engine: type[_FakeEngine], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_engine.error = DiscoveryError("")

    assert main(["scan", "."]) == EXIT_USAGE
    assert "DiscoveryError" in capsys.readouterr().err


def test_interrupt_while_building_the_parser_returns_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An interrupt before argparse runs must still be a clean 130, not a traceback."""

    def _interrupt() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("repolens.cli.build_parser", _interrupt)

    assert main(["scan", "."]) == EXIT_INTERRUPTED

    captured = capsys.readouterr()
    assert "interrupted" in captured.err
    assert "Traceback" not in captured.err


def test_interrupt_while_resolving_options_returns_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An interrupt after parsing but before scanning is also a clean 130."""

    def _interrupt(args: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("repolens.cli._scan_command", _interrupt)

    assert main(["scan", "."]) == EXIT_INTERRUPTED
    assert "interrupted" in capsys.readouterr().err


def test_interrupt_class_is_not_treated_as_an_operational_error(
    fake_engine: type[_FakeEngine], capsys: pytest.CaptureFixture[str]
) -> None:
    """KeyboardInterrupt is a BaseException: it must never fall into the exit-3 handler."""
    fake_engine.error = KeyboardInterrupt()

    assert main(["scan", "."]) == EXIT_INTERRUPTED

    err = capsys.readouterr().err
    assert "internal error" not in err
    assert "report it" not in err


def test_depth_limited_discovery_exits_three(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Directories beyond the nesting limit make the scan incomplete, not clean."""
    fake_engine.report = make_scan_report(skipped_by_depth_count=1)

    assert main(["scan", ".", "--color", "never"]) == EXIT_OPERATIONAL

    out = capsys.readouterr().out
    assert "nested deeper than the supported limit" in out
    assert "cannot be reported as clean" in out
    assert "exit code 3" in out


def test_depth_limit_with_findings_exits_one(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    fake_engine.report = make_scan_report(
        findings=[make_finding(severity=Severity.MEDIUM)], skipped_by_depth_count=2
    )

    assert main(["scan", ".", "--color", "never"]) == EXIT_FINDINGS


def test_tool_coverage_limit_exits_three(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An analyzer capped by max_tool_files did not cover the whole repository."""
    fake_engine.report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="bandit-python-security",
                status=AnalyzerStatus.COMPLETED,
                coverage_truncated=True,
            )
        ]
    )

    assert main(["scan", ".", "--color", "never"]) == EXIT_OPERATIONAL

    out = capsys.readouterr().out
    assert "covered only part of the repository" in out
    assert "bandit-python-security" in out
    assert "exit code 3" in out


def make_dir_tree(root: Path) -> Path:
    """Build a repository whose only interesting file sits past the depth limit."""
    (root / "a" / "b" / "c").mkdir(parents=True)
    (root / "a" / "b" / "c" / "buried.py").write_text("def broken(:\n", encoding="utf-8")
    (root / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    return root


def test_real_depth_limited_scan_exits_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """End-to-end through the real engine with the production depth limit lowered."""
    monkeypatch.setattr("repolens.discovery.MAX_DIRECTORY_DEPTH", 2)
    repo = make_dir_tree(tmp_path / "deep")
    (repo / "LICENSE").write_text("MIT License\nCopyright (c) 2026 Test\n", encoding="utf-8")
    (repo / "README.md").write_text("# Deep\n\nA repo.\n", encoding="utf-8")

    exit_code = main(["scan", str(repo), "--min-severity", "critical", "--color", "never"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_OPERATIONAL
    assert "nested deeper than the supported limit" in out


def test_missing_optional_tool_stays_exit_neutral(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A tool that was never installed is disclosed but does not fail the run."""
    fake_engine.report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="ruff-python-lint",
                status=AnalyzerStatus.UNAVAILABLE,
                coverage_incomplete=False,
                message="`ruff` executable was not found on PATH (optional tool not installed).",
            )
        ]
    )

    assert main(["scan", ".", "--color", "never"]) == EXIT_OK

    out = capsys.readouterr().out
    assert "optional tools are not installed" in out
    assert "started but could not complete" not in out
    assert "exit code 0" in out


def test_check_that_started_then_failed_exits_three(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A requested network check that started and failed is incomplete coverage, not a skip."""
    fake_engine.report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="osv-dependency-check",
                status=AnalyzerStatus.UNAVAILABLE,
                coverage_incomplete=True,
                message="OSV.dev lookup unavailable: OSV.dev is unreachable.",
            )
        ]
    )

    assert main(["scan", ".", "--color", "never"]) == EXIT_OPERATIONAL

    out = capsys.readouterr().out
    assert "1 check(s) started but could not complete" in out
    assert "osv-dependency-check" in out
    assert "optional tools are not installed" not in out
    assert "exit code 3" in out


def test_started_check_failure_with_findings_exits_one(
    fake_engine: type[_FakeEngine],
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    fake_engine.report = make_scan_report(
        findings=[make_finding(severity=Severity.HIGH)],
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="osv-dependency-check",
                status=AnalyzerStatus.UNAVAILABLE,
                coverage_incomplete=True,
            )
        ],
    )

    assert main(["scan", ".", "--color", "never"]) == EXIT_FINDINGS
