"""Unit tests for ScanEngine orchestration, fault isolation, and self-dogfooding."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from repolens.analyzers.base import Analyzer, AnalyzerAvailability, AnalyzerTimeoutError
from repolens.config import ScanConfig
from repolens.discovery import RepositoryContext
from repolens.engine import ScanEngine
from repolens.models import (
    AnalyzerStatus,
    Category,
    Finding,
    FindingLocation,
    FindingSource,
    Severity,
    SourceKind,
)


class _SkippedAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "skipped-analyzer"

    def is_applicable(self, context: RepositoryContext) -> bool:
        return False

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        raise AssertionError("Should not run when not applicable")


class _UnavailableAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "missing-binary-analyzer"

    def check_availability(self) -> AnalyzerAvailability:
        return AnalyzerAvailability(available=False, reason="biome binary not found on PATH")

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        raise AssertionError("Should not run when unavailable")


class _TimeoutAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "slow-analyzer"

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        raise AnalyzerTimeoutError("Exceeded 30s timeout")


class _CrashingAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "crashing-analyzer"

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        leaked = "sk-ant-" + "x" * 32
        raise RuntimeError(f"Unexpected failure with token {leaked}")


class _DuplicateAndUnsortedAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "duplicate-analyzer"

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        source = FindingSource(kind=SourceKind.DETERMINISTIC, tool="dup-tool")
        low = Finding(
            rule_id="DUP-LOW",
            category=Category.CODE_QUALITY,
            severity=Severity.LOW,
            title="Minor style issue",
            location=FindingLocation(path="src/sample/core.py", start_line=2),
            explanation="Minor style issue.",
            recommendation="Format file.",
            verification="Re-run linter.",
            source=source,
        )
        critical = Finding(
            rule_id="DUP-CRIT",
            category=Category.SECURITY,
            severity=Severity.CRITICAL,
            title="Critical flaw",
            location=FindingLocation(path="src/sample/core.py", start_line=1),
            explanation="Critical security issue.",
            recommendation="Patch immediately.",
            verification="Re-run security check.",
            source=source,
        )
        # Return critical twice and after low to verify deduplication + severity sorting
        return [low, critical, critical]


def test_engine_handles_analyzer_outcomes_deduplication_and_sorting(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    engine = ScanEngine(
        analyzers=[
            _SkippedAnalyzer(),
            _UnavailableAnalyzer(),
            _TimeoutAnalyzer(),
            _CrashingAnalyzer(),
            _DuplicateAndUnsortedAnalyzer(),
        ]
    )

    report = engine.scan(repo)
    outcomes = {o.analyzer_name: o for o in report.analyzer_outcomes}

    assert outcomes["skipped-analyzer"].status == AnalyzerStatus.SKIPPED
    assert outcomes["missing-binary-analyzer"].status == AnalyzerStatus.UNAVAILABLE
    assert outcomes["slow-analyzer"].status == AnalyzerStatus.TIMED_OUT
    assert outcomes["crashing-analyzer"].status == AnalyzerStatus.FAILED
    assert "sk-ant-" not in (outcomes["crashing-analyzer"].message or "")
    assert "REDACTED" in (outcomes["crashing-analyzer"].message or "")
    assert outcomes["duplicate-analyzer"].status == AnalyzerStatus.COMPLETED

    assert [f.rule_id for f in report.findings] == ["DUP-CRIT", "DUP-LOW"]


def test_engine_fail_fast_propagates_analyzer_errors(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    engine = ScanEngine(config=ScanConfig(fail_fast=True), analyzers=[_CrashingAnalyzer()])
    with pytest.raises(RuntimeError, match="Unexpected failure"):
        engine.scan(repo)


def test_repolens_repository_passes_self_scan() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    report = ScanEngine().scan(repo_root)

    # External tools (Ruff/Bandit/Biome) and opt-in network checks may legitimately be
    # unavailable on a contributor machine; nothing may fail outright.
    assert {o.status for o in report.analyzer_outcomes} <= {
        AnalyzerStatus.COMPLETED,
        AnalyzerStatus.SKIPPED,
        AnalyzerStatus.UNAVAILABLE,
    }
    assert not report.has_findings_at_or_above(Severity.LOW), (
        f"Self-scan reported unexpected findings: {report.findings}"
    )
    # The only tolerated advisory is the documented informational lockfile note for a
    # library that intentionally does not commit a Python lockfile.
    assert {f.rule_id for f in report.findings} <= {"RL-DEP-005"}


def test_engine_records_partial_coverage_from_analyzers(
    make_python_repo: Callable[..., Path],
) -> None:
    """A completed-but-limited analyzer must be visible in the report, not silently green."""

    class _PartialAnalyzer(Analyzer):
        @property
        def name(self) -> str:
            return "partial-analyzer"

        def is_applicable(self, context: RepositoryContext) -> bool:
            return True

        def completion_message(self) -> str | None:
            return "Only analyzed part of the repository."

        def coverage_partial(self) -> bool:
            return True

        def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
            return []

    report = ScanEngine(analyzers=[_PartialAnalyzer()]).scan(make_python_repo())
    outcome = report.analyzer_outcomes[0]

    assert outcome.status == AnalyzerStatus.COMPLETED
    assert outcome.coverage_truncated is True
    assert outcome.message == "Only analyzed part of the repository."


def test_engine_isolates_a_broken_reporting_failure_hook_and_retains_findings(
    make_python_repo: Callable[..., Path],
) -> None:
    class _BrokenReportingAnalyzer(_DuplicateAndUnsortedAnalyzer):
        def reporting_failure(self) -> str | None:
            leaked = "sk-ant-" + "y" * 32
            raise RuntimeError(f"completeness check failed with token {leaked}")

    report = ScanEngine(analyzers=[_BrokenReportingAnalyzer()]).scan(make_python_repo())
    outcome = report.analyzer_outcomes[0]
    assert outcome.status is AnalyzerStatus.FAILED
    assert outcome.findings_count == 3
    assert "Could not determine reporting completeness" in (outcome.message or "")
    assert "sk-ant-" not in (outcome.message or "")
    assert "REDACTED" in (outcome.message or "")
    assert [finding.rule_id for finding in report.findings] == ["DUP-CRIT", "DUP-LOW"]
