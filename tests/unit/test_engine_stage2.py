"""Stage 2 engine tests: analyzer lifecycle hooks and failure isolation."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from repolens.analyzers.base import Analyzer, AnalyzerAvailability
from repolens.analyzers.structure import StructureAnalyzer
from repolens.config import ScanConfig
from repolens.discovery import RepositoryContext
from repolens.engine import ScanEngine
from repolens.models import AnalyzerStatus, Finding


class _BrokenAvailability(Analyzer):
    @property
    def name(self) -> str:
        return "broken-availability"

    def check_availability(self) -> AnalyzerAvailability:
        leaked = "ghp_" + "C" * 32
        raise RuntimeError(f"probe failed with token {leaked}")

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        raise AssertionError("must not run when availability probing fails")


class _BrokenApplicability(Analyzer):
    @property
    def name(self) -> str:
        return "broken-applicability"

    def is_applicable(self, context: RepositoryContext) -> bool:
        raise ValueError("cannot determine applicability")

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        raise AssertionError("must not run when applicability fails")


class _SkippingAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "optional-network"

    def skip_reason(self, context: RepositoryContext, config: ScanConfig) -> str | None:
        return "Optional network checks are disabled by configuration."

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        raise AssertionError("must not run when skipped")


class _CompletingAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "completing-analyzer"

    def completion_message(self) -> str | None:
        return "Analyzed 3 files."

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        return []


def test_availability_probe_failure_is_isolated_and_redacted(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    report = ScanEngine(
        analyzers=[_BrokenAvailability(), _BrokenApplicability(), StructureAnalyzer()]
    ).scan(repo)

    outcomes = {outcome.analyzer_name: outcome for outcome in report.analyzer_outcomes}
    assert outcomes["broken-availability"].status == AnalyzerStatus.FAILED
    assert outcomes["broken-applicability"].status == AnalyzerStatus.FAILED
    assert outcomes["repolens-structure"].status == AnalyzerStatus.COMPLETED
    assert "ghp_" not in (outcomes["broken-availability"].message or "")
    assert "REDACTED" in (outcomes["broken-availability"].message or "")


def test_skip_reason_is_surfaced(make_python_repo: Callable[..., Path]) -> None:
    repo = make_python_repo()
    report = ScanEngine(analyzers=[_SkippingAnalyzer()]).scan(repo)
    outcome = report.analyzer_outcomes[0]
    assert outcome.status == AnalyzerStatus.SKIPPED
    assert outcome.message == "Optional network checks are disabled by configuration."


def test_completion_message_is_recorded(make_python_repo: Callable[..., Path]) -> None:
    repo = make_python_repo()
    report = ScanEngine(analyzers=[_CompletingAnalyzer()]).scan(repo)
    outcome = report.analyzer_outcomes[0]
    assert outcome.status == AnalyzerStatus.COMPLETED
    assert outcome.message == "Analyzed 3 files."


def test_default_analyzer_suite_is_registered() -> None:
    from repolens.analyzers import default_analyzers

    names = [analyzer.name for analyzer in default_analyzers()]
    assert names == [
        "repolens-structure",
        "dependency-manifests",
        "documentation-consistency",
        "testing-hygiene",
        "ruff-python-lint",
        "bandit-python-security",
        "biome-jsts-lint",
        "osv-dependency-check",
    ]


def test_gitignore_excluding_test_directory_is_reported(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    (repo / ".gitignore").write_text(
        "tests/\npackage-lock.json\n__pycache__/\n.venv/\n.env\n", encoding="utf-8"
    )
    report = ScanEngine(analyzers=[StructureAnalyzer()]).scan(repo)
    finding = next(item for item in report.findings if item.rule_id == "RL-STRUCT-012")
    assert finding.severity.value == "low"
    assert "tests" in (finding.evidence or "")
    assert "package-lock.json" in (finding.evidence or "")
