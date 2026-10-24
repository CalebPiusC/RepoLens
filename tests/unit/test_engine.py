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

    assert all(o.status == AnalyzerStatus.COMPLETED for o in report.analyzer_outcomes)
    assert report.findings == [], f"Self-scan reported unexpected findings: {report.findings}"
