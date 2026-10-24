"""Unit tests for RepoLens Pydantic v2 models and schema invariants."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from repolens.models import (
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


def _deterministic_source() -> FindingSource:
    return FindingSource(
        kind=SourceKind.DETERMINISTIC, tool="repolens-structure", tool_version="0.1.0"
    )


def test_finding_generates_stable_fingerprint_and_redacts_evidence() -> None:
    secret_token = "ghp_" + "A" * 36
    f1 = Finding(
        rule_id="RL-SEC-999",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="Hardcoded token in configuration",
        location=FindingLocation(path="src/config.py", start_line=12, end_line=12),
        evidence=f'GITHUB_TOKEN = "{secret_token}"',
        explanation=(
            "Credentials embedded in source code can be extracted by anyone with read access."
        ),
        recommendation="Load GITHUB_TOKEN from environment variables at runtime.",
        verification="Search the codebase to confirm no token literals remain.",
        source=_deterministic_source(),
    )
    f2 = Finding(
        rule_id="RL-SEC-999",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="Hardcoded token in configuration",
        location=FindingLocation(path="src/config.py", start_line=12, end_line=12),
        evidence='GITHUB_TOKEN = "different_evidence"',
        explanation=(
            "Credentials embedded in source code can be extracted by anyone with read access."
        ),
        recommendation="Load GITHUB_TOKEN from environment variables at runtime.",
        verification="Search the codebase to confirm no token literals remain.",
        source=_deterministic_source(),
    )

    assert len(f1.fingerprint) == 24
    assert f1.fingerprint == f2.fingerprint
    assert f1.evidence is not None
    assert secret_token not in f1.evidence
    assert "REDACTED" in f1.evidence


def test_finding_rejects_ai_advisory_source() -> None:
    ai_source = FindingSource(kind=SourceKind.AI_ADVISORY, tool="gemini-2.5-flash")
    with pytest.raises(ValidationError, match="deterministic"):
        Finding(
            rule_id="AI-HYPOTHESIS-1",
            category=Category.SECURITY,
            severity=Severity.HIGH,
            title="Potential race condition",
            explanation="Model suspects a race condition.",
            recommendation="Add a lock.",
            verification="Review concurrency.",
            source=ai_source,
        )


def test_ai_advisory_rejects_deterministic_source() -> None:
    with pytest.raises(ValidationError, match="ai_advisory"):
        AIAdvisory(
            advisory_id="ADV-001",
            summary="Explanation of finding.",
            suggested_improvement="Update .gitignore.",
            verification="Run git check-ignore.",
            source=_deterministic_source(),
        )


@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        "/etc/passwd",
        "../secrets.txt",
        "src/../../etc/shadow",
        "src\\windows\\path.py",
        "C:/Users/admin/file.py",
        ".",
        "bad\x00path.py",
    ],
)
def test_finding_location_rejects_unsafe_paths(bad_path: str) -> None:
    with pytest.raises(ValidationError):
        FindingLocation(path=bad_path)


def test_finding_location_validates_line_spans() -> None:
    with pytest.raises(ValidationError, match="start_line is None"):
        FindingLocation(path="src/app.py", end_line=10)

    with pytest.raises(ValidationError, match="greater than or equal"):
        FindingLocation(path="src/app.py", start_line=15, end_line=10)

    valid = FindingLocation(path="./src/app.py", start_line=5, end_line=10, column=1)
    assert valid.path == "src/app.py"


def test_scan_report_counts_and_json_roundtrip() -> None:
    f_high = Finding(
        rule_id="RL-SEC-001",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="Unignored .env file",
        location=FindingLocation(path=".env"),
        explanation="Environment file is unignored.",
        recommendation="Add .env to .gitignore.",
        verification="Run git check-ignore .env.",
        source=_deterministic_source(),
    )
    f_low = Finding(
        rule_id="RL-STRUCT-008",
        category=Category.STRUCTURE,
        severity=Severity.LOW,
        title="Missing lockfile",
        location=FindingLocation(path="package.json"),
        explanation="No lockfile committed.",
        recommendation="Commit package-lock.json.",
        verification="Check lockfile in git.",
        source=_deterministic_source(),
    )
    advisory = AIAdvisory(
        advisory_id="ADV-001",
        related_finding_fingerprints=[f_high.fingerprint],
        summary="Rotate credentials that may have lived in .env.",
        suggested_improvement="Use .env.example for templates and keep .env ignored.",
        verification="Run git log -- .env to confirm it was never committed.",
        source=FindingSource(kind=SourceKind.AI_ADVISORY, tool="gemini"),
    )

    report = ScanReport(
        repolens_version="0.1.0",
        repository_name="demo",
        scanned_at=datetime.now(tz=UTC),
        duration_ms=12.5,
        discovery=DiscoverySummary(
            total_files_scanned=4,
            total_bytes_scanned=512,
            skipped_excluded_count=1,
            skipped_symlink_count=0,
            skipped_oversized_count=0,
            sensitive_files_detected=1,
        ),
        analyzer_outcomes=[
            AnalyzerOutcome(
                analyzer_name="repolens-structure",
                status=AnalyzerStatus.COMPLETED,
                findings_count=2,
                duration_ms=4.2,
            )
        ],
        findings=[f_high, f_low],
        ai_advisories=[advisory],
    )

    sev_counts = report.counts_by_severity()
    assert sev_counts[Severity.HIGH] == 1
    assert sev_counts[Severity.LOW] == 1
    assert sev_counts[Severity.CRITICAL] == 0

    cat_counts = report.counts_by_category()
    assert cat_counts[Category.SECURITY] == 1
    assert cat_counts[Category.STRUCTURE] == 1

    assert report.has_findings_at_or_above(Severity.HIGH) is True
    assert report.has_findings_at_or_above(Severity.CRITICAL) is False

    serialized = report.model_dump_json()
    restored = ScanReport.model_validate_json(serialized)
    assert restored == report
