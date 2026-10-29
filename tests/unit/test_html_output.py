"""Unit tests for the self-contained HTML report renderer.

The renderer is exercised directly (no engine, no filesystem) so each test can state exactly
which report detail must reach the document, and hostile repository content is injected to
prove that nothing is ever interpolated into markup unescaped or into executable script.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import pytest

from repolens.html_output import render_html
from repolens.models import (
    SCHEMA_VERSION,
    AIAdvisory,
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
from repolens.reporting import evaluate

_VOID_ELEMENTS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "source",
        "track",
        "wbr",
    }
)


class _StructureCollector(HTMLParser):
    """Collect the document's element structure so tests can assert nesting is intact."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.problems: list[str] = []
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, value in attrs:
            if value is not None:
                self.attributes.append((name, value))
        if tag not in _VOID_ELEMENTS:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, value in attrs:
            if value is not None:
                self.attributes.append((name, value))

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID_ELEMENTS:
            return
        if not self.stack or self.stack[-1] != tag:
            self.problems.append(f"unexpected </{tag}> with open {self.stack[-3:]}")
            return
        self.stack.pop()

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def _parse(document: str) -> _StructureCollector:
    collector = _StructureCollector()
    collector.feed(document)
    collector.close()
    return collector


def _report(
    *,
    findings: Sequence[Finding] = (),
    outcomes: Sequence[AnalyzerOutcome] | None = None,
    repository_name: str = "sample-repo",
    languages: Sequence[str] = (),
    **discovery_overrides: object,
) -> ScanReport:
    discovery_fields: dict[str, object] = {
        "total_files_scanned": 12,
        "total_bytes_scanned": 2048,
        "skipped_excluded_count": 1,
        "skipped_symlink_count": 0,
        "skipped_oversized_count": 0,
        "sensitive_files_detected": 0,
        "truncated_by_file_limit": False,
        "truncated_by_byte_limit": False,
        "unreadable_directory_count": 0,
        "unreadable_entry_count": 0,
        "skipped_by_depth_count": 0,
        "detected_languages": list(languages),
    }
    discovery_fields.update(discovery_overrides)
    return ScanReport(
        repolens_version="0.1.0",
        repository_name=repository_name,
        scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        duration_ms=42.0,
        discovery=DiscoverySummary.model_validate(discovery_fields),
        analyzer_outcomes=list(outcomes or []),
        findings=list(findings),
    )


def _render(
    report: ScanReport, *, exit_code: int = 0, min_severity: Severity = Severity.INFO
) -> str:
    return render_html(
        report,
        exit_code=exit_code,
        min_severity=min_severity,
        target_path="sample-project",
    )


def _finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "rule_id": "RL-STRUCT-001",
        "category": Category.STRUCTURE,
        "severity": Severity.MEDIUM,
        "title": "Missing repository LICENSE file",
        "location": FindingLocation(path="LICENSE"),
        "explanation": "An explicit license is required for others to use the code.",
        "recommendation": "Add a LICENSE file at the repository root.",
        "verification": "Confirm the file exists at the repository root.",
        "source": FindingSource(
            kind=SourceKind.DETERMINISTIC, tool="repolens-structure", tool_version="0.1.0"
        ),
    }
    fields.update(overrides)
    return Finding.model_validate(fields)


# ------------------------------------------------------------------------------------
# Document structure
# ------------------------------------------------------------------------------------


def test_document_is_a_complete_balanced_html_page() -> None:
    document = _render(_report(findings=[_finding()], languages=["python"]), exit_code=1)
    collector = _parse(document)

    assert collector.problems == []
    assert collector.stack == []
    assert document.startswith("<!DOCTYPE html>")
    assert document.rstrip().endswith("</html>")
    assert collector.tags[0] == "html"


def test_document_declares_language_charset_and_responsive_viewport() -> None:
    document = _render(_report())

    assert '<html lang="en">' in document
    assert '<meta charset="utf-8">' in document
    assert 'name="viewport"' in document
    assert "width=device-width" in document


def test_document_has_landmarks_headings_and_a_skip_link() -> None:
    document = _render(_report(findings=[_finding()]))
    collector = _parse(document)

    assert "<main>" in document
    assert "<header" in document
    assert "<footer" in document
    assert 'href="#findings"' in document
    assert "h1" in collector.tags
    assert collector.tags.count("h1") == 1
    assert collector.tags.count("h2") >= 5
    assert "<nav" in document


def test_tables_have_headers_and_captions() -> None:
    document = _render(
        _report(
            findings=[_finding()],
            outcomes=[
                AnalyzerOutcome(
                    analyzer_name="repolens-structure",
                    status=AnalyzerStatus.COMPLETED,
                    findings_count=1,
                    duration_ms=3.0,
                )
            ],
        )
    )

    assert document.count("<caption>") == 2
    for table in re.findall(r"<table>.*?</table>", document, flags=re.DOTALL):
        assert '<th scope="col"' in table
        assert "<thead>" in table


# ------------------------------------------------------------------------------------
# Self-containment
# ------------------------------------------------------------------------------------


def test_report_loads_no_scripts_or_external_resources() -> None:
    document = _render(_report(findings=[_finding()])).lower()

    assert "<script" not in document
    assert "javascript:" not in document
    assert "<iframe" not in document
    assert "@import" not in document
    assert not re.search(r'(?:src|href)\s*=\s*"(?:https?:)?//', document)
    assert "http://" not in document
    assert "https://" not in document


def test_styles_are_inlined_and_cover_a_dark_theme_and_narrow_screens() -> None:
    document = _render(_report())

    assert "<style>" in document
    assert "<link" not in document
    assert "color-scheme: dark" in document
    assert "@media (max-width: 640px)" in document
    assert "@media print" in document


# ------------------------------------------------------------------------------------
# Result / status distinction
# ------------------------------------------------------------------------------------


def test_clean_scan_is_labelled_clean_and_says_so_plainly() -> None:
    document = _render(_report(), exit_code=0)

    assert "Clean scan" in document
    assert "No findings were reported for this repository." in document
    assert "Findings (0)" in document


def test_findings_scan_is_labelled_and_shows_every_finding() -> None:
    findings = [_finding(rule_id=f"RL-TEST-{index:03d}") for index in range(120)]

    document = _render(_report(findings=findings), exit_code=1)

    assert "Findings detected" in document
    assert "Findings (120)" in document
    for index in range(120):
        assert f"RL-TEST-{index:03d}" in document


def test_incomplete_scan_is_never_presented_as_clean() -> None:
    report = _report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="ruff-python-lint",
                status=AnalyzerStatus.TIMED_OUT,
                findings_count=0,
                duration_ms=30000.0,
            )
        ]
    )

    document = _render(report, exit_code=3)

    assert "Scan incomplete" in document
    assert "Clean scan" not in document
    assert "Incomplete" in document
    assert "analyzer_timed_out" in document
    assert "cannot be treated as a complete result" in document


def test_status_and_exit_code_agree_with_the_shared_verdict() -> None:
    below = _report(findings=[_finding(severity=Severity.MEDIUM)])
    at_threshold = _report(findings=[_finding(severity=Severity.HIGH)])

    assert evaluate(below, Severity.HIGH).has_findings is False
    assert evaluate(at_threshold, Severity.HIGH).has_findings is True

    hidden = _render(below, exit_code=0, min_severity=Severity.HIGH)
    assert "Clean scan" in hidden
    assert "0 of 1" in hidden
    assert "RL-STRUCT-001" in hidden  # still listed; only the verdict is thresholded

    shown = _render(at_threshold, exit_code=1, min_severity=Severity.HIGH)
    assert "Findings detected" in shown
    assert "1 of 1" in shown


# ------------------------------------------------------------------------------------
# Findings detail
# ------------------------------------------------------------------------------------


def test_finding_card_shows_rule_title_severity_location_and_guidance() -> None:
    document = _render(_report(findings=[_finding()]))

    for expected in (
        "RL-STRUCT-001",
        "Missing repository LICENSE file",
        "Medium",
        "LICENSE",
        "An explicit license is required",
        "Add a LICENSE file at the repository root.",
        "Confirm the file exists at the repository root.",
        "repolens-structure",
    ):
        assert expected in document


def test_finding_location_includes_line_numbers_when_known() -> None:
    finding = _finding(location=FindingLocation(path="src/app.py", start_line=12, end_line=14))

    document = _render(_report(findings=[finding]))

    assert "src/app.py:12" in document


def test_evidence_is_rendered_in_a_preformatted_block() -> None:
    finding = _finding(evidence="app.py:12: 'os' imported but unused")

    document = _render(_report(findings=[finding]))

    assert "<pre>" in document
    assert "app.py:12: &#x27;os&#x27; imported but unused" in document


def test_severity_is_shown_as_text_not_only_colour() -> None:
    findings = [
        _finding(rule_id="RL-CRIT-001", severity=Severity.CRITICAL),
        _finding(rule_id="RL-LOW-001", severity=Severity.LOW),
    ]

    document = _render(_report(findings=findings))

    assert ">Critical<" in document
    assert ">Low<" in document


def test_severity_summary_counts_every_severity_including_zero() -> None:
    document = _render(_report(findings=[_finding(severity=Severity.HIGH)]))

    for label in ("Critical", "High", "Medium", "Low", "Info"):
        assert f">{label}<" in document
    assert "Findings by severity" in document


# ------------------------------------------------------------------------------------
# Analyzer disclosure
# ------------------------------------------------------------------------------------


def test_unavailable_and_skipped_analyzers_are_disclosed() -> None:
    outcomes = [
        AnalyzerOutcome(
            analyzer_name="repolens-structure",
            status=AnalyzerStatus.COMPLETED,
            findings_count=0,
            duration_ms=2.0,
        ),
        AnalyzerOutcome(
            analyzer_name="ruff-python-lint",
            status=AnalyzerStatus.UNAVAILABLE,
            findings_count=0,
            duration_ms=0.0,
            message="`ruff` executable was not found on PATH.",
        ),
        AnalyzerOutcome(
            analyzer_name="biome-jsts-lint",
            status=AnalyzerStatus.SKIPPED,
            findings_count=0,
            duration_ms=0.0,
            message="Analyzer not applicable to detected repository contents.",
        ),
    ]

    document = _render(_report(outcomes=outcomes))

    assert "Analyzer coverage" in document
    assert "repolens-structure" in document
    assert "`ruff` executable was not found on PATH." in document
    assert "biome-jsts-lint" in document


def test_truncated_analyzer_coverage_is_flagged() -> None:
    outcomes = [
        AnalyzerOutcome(
            analyzer_name="osv-dependency-check",
            status=AnalyzerStatus.COMPLETED,
            findings_count=0,
            duration_ms=5.0,
            coverage_truncated=True,
        )
    ]

    document = _render(_report(outcomes=outcomes), exit_code=3)

    assert "Covered only part of the repository" in document
    assert "analyzer_coverage_truncated" in document


def test_no_registered_analyzers_is_stated_explicitly() -> None:
    document = _render(_report(outcomes=[]))

    assert "No analyzers were registered." in document


# ------------------------------------------------------------------------------------
# Discovery notes and coverage
# ------------------------------------------------------------------------------------


def test_discovery_limits_are_reported_as_notes() -> None:
    report = _report(
        truncated_by_file_limit=True,
        unreadable_directory_count=2,
        skipped_by_depth_count=1,
        skipped_oversized_count=3,
        skipped_symlink_count=1,
        unreadable_entry_count=0,
    )

    document = _render(report, exit_code=3)

    assert "Could not read 2 directories" in document
    assert "nested deeper than the supported limit" in document
    assert "maximum file count" in document
    assert "3 files exceeded the per-file size limit" in document
    assert "1 symbolic link were not followed" in document or "were not followed" in document


def test_complete_coverage_is_stated_positively() -> None:
    document = _render(_report())

    assert "Every check RepoLens set out to run completed." in document


# ------------------------------------------------------------------------------------
# Untrusted content
# ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "<script>alert(1)</script>",
        '"><img src=x onerror="alert(1)">',
        "</title><script>alert('x')</script>",
        "javascript:alert(1)",
        "&lt;already&gt; &amp; escaped",
        "\u2028line\u2029separator",
        "emoji 🚀 and ünïcöde",
    ],
)
def test_repository_derived_text_is_escaped_everywhere(hostile: str) -> None:
    finding = _finding(
        title=hostile,
        explanation=hostile,
        recommendation=hostile,
        verification=hostile,
        evidence=hostile,
    )
    report = _report(
        findings=[finding],
        repository_name=hostile,
        outcomes=[
            AnalyzerOutcome(
                analyzer_name=hostile,
                status=AnalyzerStatus.FAILED,
                findings_count=0,
                duration_ms=1.0,
                message=hostile,
            )
        ],
    )

    document = _render(report, exit_code=1)

    assert "<script" not in document.lower()
    assert "<img" not in document.lower()
    parsed = _parse(document)
    assert parsed.problems == []
    # No event-handler (or any other injected) attribute may survive escaping.
    assert [name for name, _ in parsed.attributes if name.lower().startswith("on")] == []


def test_hostile_text_survives_escaping_as_visible_text() -> None:
    document = _render(_report(findings=[_finding(title='<b>bold</b> & "quoted"')]))

    assert "&lt;b&gt;bold&lt;/b&gt; &amp; &quot;quoted&quot;" in document


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        " jav\tscript:alert(1)",
        "\tjavascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD4=",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "//evil.example.com",
        "http:evil.example.com",
        "https://",
        "https:///path",
        "",
    ],
)
def test_rule_links_reject_unsafe_or_relative_destinations(url: str) -> None:
    finding = _finding(
        source=FindingSource(kind=SourceKind.DETERMINISTIC, tool="ruff", rule_url=url)
    )

    document = _render(_report(findings=[finding]))

    assert "Rule documentation for" not in document
    assert "javascript:" not in document.lower()
    assert "data:text" not in document


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://docs.example.com/rule", "https://docs.example.com/rule"),
        ("HTTPS://docs.example.com/rule", "HTTPS://docs.example.com/rule"),
        ("  https://docs.example.com/rule  ", "https://docs.example.com/rule"),
    ],
)
def test_rule_links_are_stripped_before_they_reach_the_attribute(url: str, expected: str) -> None:
    finding = _finding(
        source=FindingSource(kind=SourceKind.DETERMINISTIC, tool="ruff", rule_url=url)
    )

    document = _render(_report(findings=[finding]))

    assert f'href="{expected}"' in document


@pytest.mark.parametrize(
    "url",
    [
        "https://docs.example.com/rule with space",
        "https://docs.example.com/\x00rule",
        "https://docs.example.com/rule\x7f",
    ],
)
def test_rule_links_with_control_characters_are_dropped(url: str) -> None:
    finding = _finding(
        source=FindingSource(kind=SourceKind.DETERMINISTIC, tool="ruff", rule_url=url)
    )

    document = _render(_report(findings=[finding]))

    assert "Rule documentation for" not in document


def test_rule_links_escape_quotes_and_markup() -> None:
    finding = _finding(
        source=FindingSource(
            kind=SourceKind.DETERMINISTIC,
            tool="ruff",
            rule_url='https://docs.example.com/"onmouseover="alert(1)',
        )
    )

    document = _render(_report(findings=[finding]))
    parsed = _parse(document)

    # The payload survives only as escaped text inside a quoted attribute, so it can never
    # become a second attribute.
    assert "&quot;onmouseover=" in document
    assert [name for name, _ in parsed.attributes if name.lower().startswith("on")] == []
    assert 'rel="noopener noreferrer"' in document


def test_rule_links_are_emitted_only_for_http_urls() -> None:
    https = _finding(
        source=FindingSource(
            kind=SourceKind.DETERMINISTIC,
            tool="ruff",
            rule_url="https://docs.astral.sh/ruff/rules/unused-import/",
        )
    )
    javascript = _finding(
        source=FindingSource(
            kind=SourceKind.DETERMINISTIC, tool="ruff", rule_url="javascript:alert(1)"
        )
    )

    document = _render(_report(findings=[https, javascript]))

    assert 'href="https://docs.astral.sh/ruff/rules/unused-import/"' in document
    assert "javascript:" not in document
    assert 'rel="noopener noreferrer"' in document


def test_no_notes_are_invented_for_a_clean_complete_report() -> None:
    document = _render(_report())

    assert "Notes" not in document
    assert "AI advisor" not in document


# ------------------------------------------------------------------------------------
# Determinism
# ------------------------------------------------------------------------------------


def test_rendering_the_same_report_twice_is_byte_identical() -> None:
    report = _report(findings=[_finding(rule_id="RL-A"), _finding(rule_id="RL-B")])

    assert _render(report, exit_code=1) == _render(report, exit_code=1)


def test_every_incomplete_reason_is_listed_in_the_footer() -> None:
    report = _report(
        unreadable_directory_count=1,
        truncated_by_byte_limit=True,
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="bandit-python-security",
                status=AnalyzerStatus.FAILED,
                findings_count=0,
                duration_ms=1.0,
            )
        ],
    )

    document = _render(report, exit_code=3)

    for reason in ("discovery_unreadable", "discovery_truncated", "analyzer_failed"):
        assert reason in document


def test_min_severity_is_reflected_in_the_document() -> None:
    document = _render(
        _report(findings=[_finding(severity=Severity.LOW)]), min_severity=Severity.HIGH
    )

    assert document.count("Severity threshold") == 1
    assert "<dd>high</dd>" in document
    assert "0 of 1" in document


def test_target_path_is_shown_when_provided() -> None:
    document = _render(_report())

    assert "sample-project" in document


def test_render_html_accepts_a_callable_built_report() -> None:
    """Guard against the renderer drifting into a second analysis model."""
    build: Callable[..., ScanReport] = _report
    report = build(findings=[])

    assert "RepoLens" in _render(report)


def test_footer_reports_the_schema_version_of_the_rendered_report() -> None:
    report = _report().model_copy(update={"schema_version": "1.0.0"})

    document = _render(report)

    assert "document schema" in document
    assert "1.0.0" in document
    assert f"document schema {SCHEMA_VERSION}" not in document


def test_ai_advisory_count_agrees_with_its_verb() -> None:
    one = _report().model_copy(
        update={
            "ai_advisories": [
                AIAdvisory(
                    advisory_id="ADV-1",
                    summary="Consider X before release.",
                    suggested_improvement="Add a regression test for X.",
                    verification="Confirm the new test fails without the fix.",
                    related_finding_fingerprints=[],
                    source=FindingSource(kind=SourceKind.AI_ADVISORY, tool="gemini"),
                )
            ]
        }
    )

    document = _render(one)

    assert "1 AI advisory is present in the report data" in document


def test_hostile_location_paths_are_escaped() -> None:
    hostile = '"><img src=x onerror=alert(1)>.py'
    finding = _finding(location=FindingLocation(path=hostile, start_line=1))

    document = _render(_report(findings=[finding]))

    assert "<img" not in document.lower()
    assert [name for name, _ in _parse(document).attributes if name.lower().startswith("on")] == []


# ------------------------------------------------------------------------------------
# Documentation consistency
# ------------------------------------------------------------------------------------


def _html_readme_section() -> str:
    """Return the README's HTML report section, with line wrapping normalised."""
    readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
    start = readme.index("## HTML report")
    end = readme.index("## Optional external tools")
    return " ".join(readme[start:end].split())


def test_readme_documents_the_html_report_contract() -> None:
    section = _html_readme_section()

    assert "--format html" in section
    assert "--output" in section
    assert "no JavaScript" in section
    assert "self-contained" in section
    assert "html.escape(quote=True)" in section
    assert "Exit-code preserving" in section


def test_readme_documents_the_output_file_guarantees() -> None:
    section = _html_readme_section()

    # The documented behaviour must match the atomic writer: replacement, permissions,
    # symlink handling, and the usage error for a non-HTML format.
    assert "requires `--format html`" in section
    assert "usage error (exit `2`)" in section
    assert "never truncates an existing report" in section
    assert "64 & ~umask" in section or "0644 & ~umask" in section
    assert "symbolic" in section


def test_readme_confirmation_message_matches_the_cli() -> None:
    """The documented stderr line must be the one the CLI actually prints."""
    section = _html_readme_section()
    prefix = "repolens: wrote HTML report to "

    assert prefix in section


def test_header_omits_a_target_path_when_none_is_given() -> None:
    document = render_html(_report(), exit_code=0)

    assert "Static analysis report" in document
    assert "Static analysis report for" not in document


def test_repository_wide_findings_are_labelled_as_such() -> None:
    finding = _finding(location=None)

    document = _render(_report(findings=[finding]))

    assert "(repository-wide)" in document


def test_started_but_incomplete_checks_are_explained() -> None:
    outcomes = [
        AnalyzerOutcome(
            analyzer_name="osv-dependency-check",
            status=AnalyzerStatus.FAILED,
            findings_count=0,
            duration_ms=3.0,
            message="OSV.dev request failed.",
            coverage_incomplete=True,
        )
    ]

    document = _render(_report(outcomes=outcomes), exit_code=3)

    assert "OSV.dev request failed." in document
    assert "Started but did not complete" in document


def test_unreadable_entries_are_reported_with_the_singular_form() -> None:
    document = _render(_report(unreadable_entry_count=1), exit_code=3)

    assert "1 entry" in document
    assert "1 entries" not in document


def test_malformed_rule_urls_are_dropped_instead_of_raising() -> None:
    # ``urlsplit`` raises ValueError for an unbalanced IPv6 host.
    finding = _finding(
        source=FindingSource(
            kind=SourceKind.DETERMINISTIC, tool="ruff", rule_url="https://[::1/rule"
        )
    )

    document = _render(_report(findings=[finding]))

    assert "Rule documentation for" not in document
    assert _parse(document).problems == []


def test_rule_links_never_embed_credentials() -> None:
    finding = _finding(
        source=FindingSource(
            kind=SourceKind.DETERMINISTIC,
            tool="ruff",
            rule_url="https://user:secret@example.com/rule",
        )
    )

    document = _render(_report(findings=[finding]))

    assert "Rule documentation for" not in document
    assert "secret" not in document
