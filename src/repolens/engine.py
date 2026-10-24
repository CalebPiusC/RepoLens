"""Shared analysis engine orchestrating discovery, analyzers, and report generation."""

from __future__ import annotations

import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from repolens import __version__
from repolens.analyzers import (
    Analyzer,
    AnalyzerTimeoutError,
    AnalyzerUnavailableError,
    default_analyzers,
)
from repolens.config import ScanConfig
from repolens.discovery import discover_repository
from repolens.models import AnalyzerOutcome, AnalyzerStatus, Finding, ScanReport


def _finding_sort_key(finding: Finding) -> tuple[int, str, str, int, str, str]:
    loc_path = finding.location.path if finding.location is not None else ""
    loc_line = (
        finding.location.start_line
        if finding.location is not None and finding.location.start_line is not None
        else 0
    )
    return (
        -finding.severity.rank,
        finding.category.value,
        loc_path,
        loc_line,
        finding.rule_id,
        finding.fingerprint,
    )


def _deduplicate_and_sort(findings: Sequence[Finding]) -> list[Finding]:
    seen_fingerprints: set[str] = set()
    unique: list[Finding] = []
    for finding in sorted(findings, key=_finding_sort_key):
        if finding.fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(finding.fingerprint)
        unique.append(finding)
    return unique


class ScanEngine:
    """Shared deterministic repository scanner used by both CLI and server interfaces."""

    def __init__(
        self,
        *,
        config: ScanConfig | None = None,
        analyzers: Sequence[Analyzer] | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.analyzers: tuple[Analyzer, ...] = (
            tuple(analyzers) if analyzers is not None else tuple(default_analyzers())
        )

    def scan(self, repo_path: Path | str) -> ScanReport:
        """Scan ``repo_path`` safely and return an immutable ``ScanReport``."""
        started = time.perf_counter()
        scanned_at = datetime.now(tz=UTC)
        target = Path(repo_path)

        context = discover_repository(target, self.config)

        collected_findings: list[Finding] = []
        outcomes: list[AnalyzerOutcome] = []

        for analyzer in self.analyzers:
            # Applicability and availability probing are isolated so a misbehaving
            # analyzer cannot abort the whole scan before it even runs.
            try:
                applicable = analyzer.is_applicable(context)
                skip_reason = analyzer.skip_reason(context, self.config) if applicable else None
                availability = analyzer.check_availability() if applicable else None
            except Exception as exc:
                if self.config.fail_fast:
                    raise
                outcomes.append(
                    AnalyzerOutcome(
                        analyzer_name=_safe_analyzer_name(analyzer),
                        status=AnalyzerStatus.FAILED,
                        message=f"{type(exc).__name__}: {exc}",
                    )
                )
                continue

            if not applicable:
                outcomes.append(
                    AnalyzerOutcome(
                        analyzer_name=analyzer.name,
                        status=AnalyzerStatus.SKIPPED,
                        message="Analyzer not applicable to detected repository contents.",
                    )
                )
                continue

            if skip_reason is not None:
                outcomes.append(
                    AnalyzerOutcome(
                        analyzer_name=analyzer.name,
                        status=AnalyzerStatus.SKIPPED,
                        message=skip_reason,
                    )
                )
                continue

            if availability is not None and not availability.available:
                outcomes.append(
                    AnalyzerOutcome(
                        analyzer_name=analyzer.name,
                        status=AnalyzerStatus.UNAVAILABLE,
                        message=availability.reason or "Required analyzer dependency unavailable.",
                    )
                )
                continue

            analyzer_start = time.perf_counter()
            try:
                analyzer_findings = analyzer.analyze(context, self.config)
            except AnalyzerTimeoutError as exc:
                analyzer_duration = (time.perf_counter() - analyzer_start) * 1000.0
                outcomes.append(
                    AnalyzerOutcome(
                        analyzer_name=analyzer.name,
                        status=AnalyzerStatus.TIMED_OUT,
                        duration_ms=analyzer_duration,
                        message=str(exc) or "Analyzer timed out.",
                    )
                )
            except AnalyzerUnavailableError as exc:
                analyzer_duration = (time.perf_counter() - analyzer_start) * 1000.0
                outcomes.append(
                    AnalyzerOutcome(
                        analyzer_name=analyzer.name,
                        status=AnalyzerStatus.UNAVAILABLE,
                        duration_ms=analyzer_duration,
                        message=str(exc) or "Required analyzer dependency became unavailable.",
                    )
                )
            except Exception as exc:
                if self.config.fail_fast:
                    raise
                analyzer_duration = (time.perf_counter() - analyzer_start) * 1000.0
                outcomes.append(
                    AnalyzerOutcome(
                        analyzer_name=analyzer.name,
                        status=AnalyzerStatus.FAILED,
                        duration_ms=analyzer_duration,
                        message=f"{type(exc).__name__}: {exc}",
                    )
                )
            else:
                analyzer_duration = (time.perf_counter() - analyzer_start) * 1000.0
                collected_findings.extend(analyzer_findings)
                outcomes.append(
                    AnalyzerOutcome(
                        analyzer_name=analyzer.name,
                        status=AnalyzerStatus.COMPLETED,
                        findings_count=len(analyzer_findings),
                        duration_ms=analyzer_duration,
                        message=analyzer.completion_message(),
                    )
                )

        ordered_findings = _deduplicate_and_sort(collected_findings)
        total_duration = (time.perf_counter() - started) * 1000.0

        return ScanReport(
            repolens_version=__version__,
            repository_name=context.repository_name,
            scanned_at=scanned_at,
            duration_ms=total_duration,
            discovery=context.summary,
            analyzer_outcomes=outcomes,
            findings=ordered_findings,
        )


def _safe_analyzer_name(analyzer: Analyzer) -> str:
    """Best-effort analyzer name for outcomes when ``analyzer.name`` itself is broken."""
    try:
        return analyzer.name
    except Exception:  # pragma: no cover - defensive only
        return type(analyzer).__name__
