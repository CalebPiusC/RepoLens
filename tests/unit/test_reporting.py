"""Unit tests for terminal report rendering and result evaluation."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from repolens.models import AnalyzerOutcome, AnalyzerStatus, Finding, ScanReport, Severity
from repolens.reporting import RenderOptions, evaluate, format_bytes, render_report


def test_clean_report_renders_no_findings_message(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    output = render_report(make_scan_report(), exit_code=0)

    assert "RepoLens 0.1.0" in output
    assert "sample-repo" in output
    assert "No findings detected." in output
    assert "no findings at or above 'info' severity (exit code 0)" in output
    assert "\x1b[" not in output


def test_findings_include_severity_rule_location_and_message(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    finding = make_finding(path="src/app.py", start_line=42, title="Missing test coverage")
    output = render_report(make_scan_report(findings=[finding]), exit_code=1)

    assert "SEVERITY" in output
    assert "MEDIUM" in output
    assert "RL-STRUCT-001" in output
    assert "src/app.py:42" in output
    assert "Missing test coverage" in output
    assert "(exit code 1)" in output


def test_findings_without_location_render_placeholder(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    output = render_report(make_scan_report(findings=[make_finding(path=None)]))
    assert "Missing repository LICENSE file" in output
    assert " - " in output or "\n  -" in output or "  -  " in output


def test_severity_counts_and_ordering(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    findings = [
        make_finding(rule_id="RL-LOW-001", severity=Severity.LOW),
        make_finding(rule_id="RL-CRIT-001", severity=Severity.CRITICAL),
        make_finding(rule_id="RL-MED-001", severity=Severity.MEDIUM),
    ]
    # The engine sorts by severity; the renderer preserves the given report order.
    report = make_scan_report(findings=findings)
    output = render_report(report)

    summary_line = next(line for line in output.splitlines() if "critical 1" in line)
    assert "high 0" in summary_line
    assert "medium 1" in summary_line
    assert "low 1" in summary_line
    assert "info 0" in summary_line
    assert "3 finding(s) detected at or above 'info' severity" in output


def test_min_severity_filters_display_and_notes_hidden_findings(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    findings = [
        make_finding(rule_id="RL-MED-001", severity=Severity.MEDIUM),
        make_finding(rule_id="RL-INFO-001", severity=Severity.INFO),
    ]
    output = render_report(
        make_scan_report(findings=findings),
        options=RenderOptions(min_severity=Severity.HIGH),
        exit_code=0,
    )

    assert "none at or above 'high' severity (2 below threshold)" in output
    assert "RL-MED-001" not in output
    assert "no findings at or above 'high' severity (exit code 0)" in output
    assert "only findings at or above 'high' severity affect the result" in output


def test_max_findings_truncates_with_notice(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    findings = [
        make_finding(rule_id=f"RL-RULE-{index:03d}", severity=Severity.HIGH) for index in range(5)
    ]
    output = render_report(
        make_scan_report(findings=findings),
        options=RenderOptions(max_findings=2),
    )

    assert "RL-RULE-000" in output
    assert "RL-RULE-001" in output
    assert "RL-RULE-002" not in output
    assert "3 more finding(s) not shown" in output


def test_long_titles_and_paths_are_clipped(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    finding = make_finding(
        title="Overly long finding title " + "x" * 210,
        path="/".join(["nested-directory" * 3] * 4) + "/module.py",
    )
    output = render_report(make_scan_report(findings=[finding]))

    assert "..." in output
    assert "x" * 210 not in output
    assert max(len(line) for line in output.splitlines()) < 220


def test_multiline_title_is_collapsed_to_single_line(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    finding = make_finding(title="Problem\nwith\ttabs   and spaces")
    output = render_report(make_scan_report(findings=[finding]))
    assert "Problem with tabs and spaces" in output


def test_analyzer_table_reports_status_and_notes(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    outcomes = [
        AnalyzerOutcome(
            analyzer_name="repolens-structure",
            status=AnalyzerStatus.COMPLETED,
            findings_count=1,
            duration_ms=4.0,
        ),
        AnalyzerOutcome(
            analyzer_name="ruff-python-lint",
            status=AnalyzerStatus.UNAVAILABLE,
            message="`ruff` executable was not found on PATH.",
        ),
        AnalyzerOutcome(
            analyzer_name="biome-jsts-lint",
            status=AnalyzerStatus.SKIPPED,
            message="Analyzer not applicable to detected repository contents.",
        ),
    ]
    output = render_report(make_scan_report(findings=[make_finding()], outcomes=outcomes))

    assert "completed" in output
    assert "unavailable" in output
    assert "skipped" in output
    assert "`ruff` executable was not found on PATH." in output
    assert "1 analyzer(s) unavailable because optional tools are not installed" in output


def test_failed_analyzer_marks_scan_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    outcomes = [
        AnalyzerOutcome(
            analyzer_name="bandit-python-security",
            status=AnalyzerStatus.FAILED,
            message="Bandit exited with status 2.",
        )
    ]
    report = make_scan_report(outcomes=outcomes)
    verdict = evaluate(report)
    output = render_report(report, exit_code=3)

    assert verdict.is_incomplete is True
    assert verdict.is_clean is False
    assert "scan incomplete — no confirmed findings at or above 'info' severity" in output
    assert "1 analyzer(s) failed or timed out" in output
    assert "bandit-python-security" in output


def test_timed_out_analyzer_is_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    outcomes = [AnalyzerOutcome(analyzer_name="slow-analyzer", status=AnalyzerStatus.TIMED_OUT)]
    verdict = evaluate(make_scan_report(outcomes=outcomes))
    assert verdict.is_incomplete is True


def test_verdict_flags_findings_above_threshold(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(
        findings=[
            make_finding(rule_id="RL-LOW-001", severity=Severity.LOW),
            make_finding(rule_id="RL-HIGH-001", severity=Severity.HIGH),
        ]
    )
    verdict = evaluate(report, Severity.HIGH)

    assert verdict.has_findings is True
    assert verdict.total_findings == 2
    assert [finding.rule_id for finding in verdict.findings_at_or_above] == ["RL-HIGH-001"]
    assert verdict.hidden_findings == 1
    assert verdict.is_clean is False

    assert evaluate(report, Severity.CRITICAL).is_clean is True


def test_discovery_truncation_produces_warning(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    output = render_report(make_scan_report(truncated_by_file_limit=True), exit_code=0)
    assert "discovery stopped early after reaching the maximum file count limit" in output
    assert "results may be incomplete" in output


def test_byte_limit_truncation_is_reported(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    output = render_report(make_scan_report(truncated_by_byte_limit=True))
    assert "maximum total bytes" in output

    both = render_report(
        make_scan_report(truncated_by_file_limit=True, truncated_by_byte_limit=True)
    )
    assert "maximum file count and maximum total bytes" in both


def test_color_output_uses_ansi_only_when_enabled(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(findings=[make_finding(severity=Severity.HIGH)])

    plain = render_report(report, options=RenderOptions(color=False))
    colored = render_report(report, options=RenderOptions(color=True))

    assert "\x1b[" not in plain
    assert "\x1b[91m" in colored
    # Styling must not change the visible text content.
    stripped = colored.replace("\x1b[0m", "")
    for code in ("\x1b[1m", "\x1b[2m", "\x1b[91m", "\x1b[92m", "\x1b[93m", "\x1b[96m"):
        stripped = stripped.replace(code, "")
    assert stripped == plain


def test_report_without_analyzers_renders_notice(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    output = render_report(make_scan_report(outcomes=[]))
    assert "No analyzers were registered." in output


def test_target_path_is_rendered_when_provided(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    output = render_report(make_scan_report(), target_path="/srv/projects/some-repo")
    assert "Target: /srv/projects/some-repo" in output


def test_sensitive_severity_labels_are_uppercase(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(findings=[make_finding(severity=Severity.CRITICAL)])
    output = render_report(report)
    assert "CRITICAL" in output
    assert "critical" in output  # summary line uses lowercase labels


@pytest.mark.parametrize(
    ("size", "expected"),
    [
        (0, "0 B"),
        (512, "512 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (1024 * 1024, "1.0 MiB"),
        (3 * 1024 * 1024 * 1024, "3.0 GiB"),
    ],
)
def test_format_bytes(size: int, expected: str) -> None:
    assert format_bytes(size) == expected


def test_terabyte_scale_byte_formatting() -> None:
    assert format_bytes(2 * 1024**4) == "2.0 TiB"


def test_findings_header_reports_hidden_below_threshold_count(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(
        findings=[
            make_finding(rule_id="RL-HIGH-001", severity=Severity.HIGH),
            make_finding(rule_id="RL-LOW-001", severity=Severity.LOW),
        ]
    )
    output = render_report(report, options=RenderOptions(min_severity=Severity.MEDIUM))

    assert "1 at or above 'medium' severity, 1 below threshold" in output
    assert "1 finding(s) below the 'medium' threshold are hidden" in output


def test_incomplete_scan_with_findings_reports_both(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    outcomes = [
        AnalyzerOutcome(analyzer_name="flaky", status=AnalyzerStatus.FAILED, message="boom")
    ]
    report = make_scan_report(findings=[make_finding(severity=Severity.HIGH)], outcomes=outcomes)
    output = render_report(report, exit_code=1)

    assert "but the scan is incomplete" in output
    assert "1 analyzer(s) failed or timed out" in output
    assert "(exit code 1)" in output


def test_info_only_findings_use_non_red_result_style(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(findings=[make_finding(severity=Severity.INFO)])
    colored = render_report(report, options=RenderOptions(color=True))
    # INFO-only findings below the medium threshold are highlighted yellow, not red.
    assert "\x1b[93m" in colored
    assert "1 finding(s) detected at or above 'info' severity" in colored


# --------------------------------------------------------------------------------------
# Severity accounting: counts describe the report, the threshold only gates the exit code
# --------------------------------------------------------------------------------------


def test_severity_counts_include_findings_below_the_threshold(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    """Regression: counts used to be filtered by --min-severity while claiming not to be."""
    findings = [
        make_finding(rule_id="RL-CRIT-001", severity=Severity.CRITICAL),
        make_finding(rule_id="RL-LOW-001", severity=Severity.LOW),
        make_finding(rule_id="RL-LOW-002", severity=Severity.LOW),
        make_finding(rule_id="RL-INFO-001", severity=Severity.INFO),
    ]
    output = render_report(
        make_scan_report(findings=findings),
        options=RenderOptions(min_severity=Severity.HIGH),
        exit_code=1,
    )

    counts_line = next(line for line in output.splitlines() if "critical 1" in line)
    assert "high 0" in counts_line
    assert "medium 0" in counts_line
    assert "low 2" in counts_line
    assert "info 1" in counts_line

    # The total is the real number of findings, not the filtered subset.
    assert "total 4 finding(s) · 1 at or above 'high' severity (3 below)" in output
    assert "1 finding(s) detected at or above 'high' severity (exit code 1)" in output


def test_counts_line_is_unfiltered_when_threshold_is_info(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(
        findings=[
            make_finding(rule_id="RL-MED-001", severity=Severity.MEDIUM),
            make_finding(rule_id="RL-LOW-001", severity=Severity.LOW),
        ]
    )
    output = render_report(report, exit_code=1)

    assert "medium 1" in output
    assert "low 1" in output
    assert "total 2 finding(s)" in output
    assert "at or above 'info' severity (0 below)" not in output


def test_threshold_note_does_not_overclaim_what_is_counted(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    output = render_report(
        make_scan_report(findings=[make_finding(severity=Severity.LOW)]),
        options=RenderOptions(min_severity=Severity.HIGH),
        exit_code=0,
    )

    assert "only findings at or above 'high' severity affect the result" in output
    assert "every finding is counted in the summary above" in output
    assert "every severity is counted above" not in output


# --------------------------------------------------------------------------------------
# Incomplete discovery
# --------------------------------------------------------------------------------------


def test_unreadable_directory_makes_the_scan_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(unreadable_directory_count=1)
    verdict = evaluate(report)

    assert verdict.discovery_incomplete is True
    assert verdict.is_incomplete is True
    assert verdict.is_clean is False

    output = render_report(report, exit_code=3)
    assert "could not read 1 directory, so the scan is incomplete" in output
    assert "scan incomplete" in output
    assert "(exit code 3)" in output


def test_unreadable_entries_are_pluralized_and_reported(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(unreadable_directory_count=2, unreadable_entry_count=3)
    output = render_report(report, exit_code=3)

    assert "could not read 2 directories and 3 entries" in output


def test_truncation_alone_makes_the_scan_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    verdict = evaluate(make_scan_report(truncated_by_byte_limit=True))

    assert verdict.discovery_truncated is True
    assert verdict.discovery_incomplete is True
    assert verdict.is_clean is False


def test_complete_discovery_is_not_flagged(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    verdict = evaluate(make_scan_report())

    assert verdict.discovery_incomplete is False
    assert verdict.is_clean is True


def test_oversized_and_symlinked_files_are_disclosed(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(skipped_oversized_count=4, skipped_symlink_count=1)
    output = render_report(report)

    assert "4 file(s) exceeded the per-file size limit" in output
    assert "1 symbolic link(s) were not followed" in output
    # Disclosure only: policy skips do not make a scan incomplete.
    assert evaluate(report).is_incomplete is False


# --------------------------------------------------------------------------------------
# Nesting-depth limit and analyzer coverage limits
# --------------------------------------------------------------------------------------


def test_depth_limited_discovery_makes_the_scan_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(skipped_by_depth_count=1)
    verdict = evaluate(report)

    assert verdict.discovery_depth_limited is True
    assert verdict.discovery_incomplete is True
    assert verdict.is_incomplete is True
    assert verdict.is_clean is False


def test_depth_limit_is_explained_with_the_supported_limit(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    from repolens.discovery import MAX_DIRECTORY_DEPTH

    output = render_report(make_scan_report(skipped_by_depth_count=2), exit_code=3)

    assert "discovery skipped 2 directories nested deeper than the supported limit" in output
    assert f"limit of {MAX_DIRECTORY_DEPTH} levels" in output
    assert "cannot be reported as clean" in output
    assert "Result: scan incomplete" in output


def test_depth_note_is_absent_for_normal_repositories(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    output = render_report(make_scan_report())

    assert "nested deeper than" not in output


def test_depth_limit_plus_findings_reports_both(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(
        findings=[make_finding(severity=Severity.HIGH)], skipped_by_depth_count=1
    )

    output = render_report(report, exit_code=1)

    assert "but the scan is incomplete" in output
    assert "nested deeper than the supported limit" in output
    assert "(exit code 1)" in output


def test_analyzer_coverage_limit_makes_the_scan_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="ruff-python-lint",
                status=AnalyzerStatus.COMPLETED,
                coverage_truncated=True,
                message="Ruff only analyzed 2000 Python file(s).",
            )
        ]
    )
    verdict = evaluate(report)

    assert verdict.partial_coverage_analyzers[0].analyzer_name == "ruff-python-lint"
    assert verdict.is_incomplete is True

    output = render_report(report, exit_code=3)
    assert "1 analyzer(s) covered only part of the repository" in output
    assert "ruff-python-lint" in output
    assert "The scan is incomplete." in output


def test_completed_analyzer_without_truncation_is_not_flagged(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(analyzer_name="ruff-python-lint", status=AnalyzerStatus.COMPLETED)
        ]
    )

    assert evaluate(report).partial_coverage_analyzers == ()
    assert evaluate(report).is_incomplete is False


def test_excluded_directories_are_disclosed_on_the_discovery_line(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report()
    report = report.model_copy(
        update={"discovery": report.discovery.model_copy(update={"skipped_excluded_count": 3})}
    )

    output = render_report(report)

    assert "3 dirs excluded" in output
    assert evaluate(report).is_incomplete is False


def test_failed_analyzer_that_was_also_coverage_truncated_stays_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """Q3: the two signals are independent; either one makes the verdict incomplete."""
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="ruff-python-lint",
                status=AnalyzerStatus.FAILED,
                coverage_truncated=True,
                message="tool crashed after the file cap was hit",
            )
        ]
    )
    verdict = evaluate(report)

    assert verdict.is_incomplete is True
    assert [o.analyzer_name for o in verdict.incomplete_analyzers] == ["ruff-python-lint"]
    # A failed run is reported as failed, not as "covered only part".
    assert verdict.partial_coverage_analyzers == ()


def test_timed_out_analyzer_with_coverage_flag_is_not_double_counted(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="biome-jsts-lint",
                status=AnalyzerStatus.TIMED_OUT,
                coverage_truncated=True,
            )
        ]
    )
    output = render_report(report, exit_code=3)

    assert "1 analyzer(s) failed or timed out" in output
    assert "covered only part of the repository" not in output


def test_multiple_partial_analyzers_are_counted_and_named(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """Q4: the warning count must match the number of affected analyzers."""
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="ruff-python-lint",
                status=AnalyzerStatus.COMPLETED,
                coverage_truncated=True,
            ),
            AnalyzerOutcome(
                analyzer_name="bandit-python-security",
                status=AnalyzerStatus.COMPLETED,
                coverage_truncated=True,
            ),
            AnalyzerOutcome(analyzer_name="repolens-structure", status=AnalyzerStatus.COMPLETED),
        ]
    )
    output = render_report(report, exit_code=3)

    assert "2 analyzer(s) covered only part of the repository" in output
    assert "ruff-python-lint, bandit-python-security" in output
    assert (
        "repolens-structure" not in output.split("built-in limit was reached:")[1].splitlines()[0]
    )


def test_partial_coverage_with_findings_still_exits_one(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(
        findings=[make_finding(severity=Severity.HIGH)],
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="ruff-python-lint",
                status=AnalyzerStatus.COMPLETED,
                coverage_truncated=True,
            )
        ],
    )

    from repolens.cli import EXIT_FINDINGS, determine_exit_code

    assert determine_exit_code(report) == EXIT_FINDINGS
    assert "but the scan is incomplete" in render_report(report, exit_code=1)
