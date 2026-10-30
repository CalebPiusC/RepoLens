"""Unit tests for the opt-in OSV.dev advisory analyzer (external service mocked)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from repolens.analyzers.advisories import OsvVulnerabilityAnalyzer
from repolens.analyzers.structure import StructureAnalyzer
from repolens.config import ScanConfig
from repolens.engine import ScanEngine
from repolens.models import AnalyzerStatus, Confidence, Severity
from repolens.osv import (
    OsvNetworkError,
    OsvPackage,
    OsvResponseError,
    OsvTimeoutError,
    OsvVulnerability,
)


class FakeClient:
    def __init__(
        self,
        *,
        vulnerabilities: Sequence[OsvVulnerability] = (),
        error: Exception | None = None,
    ) -> None:
        self._vulnerabilities = list(vulnerabilities)
        self._error = error
        self.received: list[OsvPackage] = []

    def query(self, packages: Sequence[OsvPackage]) -> list[OsvVulnerability]:
        self.received.extend(packages)
        if self._error is not None:
            raise self._error
        return self._vulnerabilities


def _pinned_python_repo(tmp_path: Path) -> Path:
    root = tmp_path / "pinned"
    root.mkdir()
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (root / "README.md").write_text("# Pinned\n", encoding="utf-8")
    (root / ".gitignore").write_text("__pycache__/\n.venv/\n.env\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "pinned"\nversion = "1.0.0"\n'
        'dependencies = ["requests==2.31.0"]\n'
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    return root


def _vuln() -> OsvVulnerability:
    return OsvVulnerability(
        vuln_id="GHSA-abcd-efgh-ijkl",
        package=OsvPackage(name="requests", version="2.31.0", ecosystem="PyPI"),
        summary="Requests leaks credentials on redirect",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        aliases=("CVE-2024-99999",),
        fixed_versions=("2.32.0",),
    )


def test_network_checks_disabled_skips_analyzer(tmp_path: Path) -> None:
    repo = _pinned_python_repo(tmp_path)
    report = ScanEngine(
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=lambda config: FakeClient())]
    ).scan(repo)

    outcome = report.analyzer_outcomes[0]
    assert outcome.status == AnalyzerStatus.SKIPPED
    assert "Network dependency checks are disabled" in (outcome.message or "")
    assert report.findings == []


def test_vulnerabilities_become_deterministic_security_findings(tmp_path: Path) -> None:
    repo = _pinned_python_repo(tmp_path)
    client = FakeClient(vulnerabilities=[_vuln()])
    config = ScanConfig(enable_network_checks=True)
    report = ScanEngine(
        config=config,
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client)],
    ).scan(repo)

    outcome = report.analyzer_outcomes[0]
    assert outcome.status == AnalyzerStatus.COMPLETED
    assert outcome.findings_count == 1

    finding = report.findings[0]
    assert finding.rule_id == "OSV-GHSA-abcd-efgh-ijkl"
    assert finding.category.value == "security"
    assert finding.severity is Severity.HIGH
    assert finding.source.tool == "osv.dev"
    assert finding.source.rule_url == "https://osv.dev/vulnerability/GHSA-abcd-efgh-ijkl"
    assert finding.location is not None
    # The pin is declared by both manifests; either deterministic source is acceptable.
    assert finding.location.path in {"pyproject.toml", "requirements.txt"}
    assert "2.32.0" in finding.recommendation
    assert "CVE-2024-99999" in finding.explanation

    # Only package coordinates leave the process.
    assert [(p.name, p.version, p.ecosystem) for p in client.received] == [
        ("requests", "2.31.0", "PyPI")
    ]


def test_duplicate_vulnerability_across_sources_is_reported_once(tmp_path: Path) -> None:
    repo = _pinned_python_repo(tmp_path)
    client = FakeClient(vulnerabilities=[_vuln(), _vuln()])
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client)],
    ).scan(repo)
    assert len(report.findings) == 1


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (OsvTimeoutError("timed out"), AnalyzerStatus.TIMED_OUT),
        (OsvNetworkError("offline"), AnalyzerStatus.UNAVAILABLE),
        (OsvResponseError("bad payload"), AnalyzerStatus.FAILED),
    ],
)
def test_osv_failures_are_reported_without_aborting_the_scan(
    tmp_path: Path, error: Exception, expected_status: AnalyzerStatus
) -> None:
    repo = _pinned_python_repo(tmp_path)
    client = FakeClient(error=error)
    config = ScanConfig(enable_network_checks=True)
    report = ScanEngine(
        config=config,
        analyzers=[
            StructureAnalyzer(),
            OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client),
        ],
    ).scan(repo)

    outcomes = {outcome.analyzer_name: outcome for outcome in report.analyzer_outcomes}
    assert outcomes["osv-dependency-check"].status == expected_status
    assert outcomes["repolens-structure"].status == AnalyzerStatus.COMPLETED
    assert report.findings == []


def test_analyzer_not_applicable_without_locked_packages(tmp_path: Path) -> None:
    root = tmp_path / "unlocked"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=lambda cfg: FakeClient())],
    ).scan(root)
    assert report.analyzer_outcomes[0].status == AnalyzerStatus.SKIPPED
    assert "not applicable" in (report.analyzer_outcomes[0].message or "").lower()


def test_package_limit_is_enforced(tmp_path: Path) -> None:
    repo = _pinned_python_repo(tmp_path)
    (repo / "requirements.txt").write_text("requests==2.31.0\nurllib3==2.2.1\n", encoding="utf-8")
    client = FakeClient()
    config = ScanConfig(enable_network_checks=True, max_osv_packages=1)
    ScanEngine(
        config=config,
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client)],
    ).scan(repo)
    assert len(client.received) == 1


def test_analyzer_reports_no_network_when_transport_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _pinned_python_repo(tmp_path)

    def _explode(config: ScanConfig) -> FakeClient:
        return FakeClient(error=OsvNetworkError("OSV.dev is unreachable from this environment."))

    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=_explode)],
    ).scan(repo)
    assert report.analyzer_outcomes[0].status == AnalyzerStatus.UNAVAILABLE
    assert "unreachable" in (report.analyzer_outcomes[0].message or "")


def test_findings_capped_by_config(tmp_path: Path) -> None:
    repo = _pinned_python_repo(tmp_path)
    vulnerabilities = [
        OsvVulnerability(
            vuln_id=f"GHSA-test-{index:04d}",
            package=OsvPackage(name="requests", version="2.31.0", ecosystem="PyPI"),
            summary="s",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
        )
        for index in range(5)
    ]
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True, max_findings_per_analyzer=2),
        analyzers=[
            OsvVulnerabilityAnalyzer(
                client_factory=lambda cfg: FakeClient(vulnerabilities=vulnerabilities)
            )
        ],
    ).scan(repo)
    assert len(report.findings) == 2


def test_finding_without_location_when_source_is_unknown(tmp_path: Path) -> None:
    repo = _pinned_python_repo(tmp_path)
    vuln = OsvVulnerability(
        vuln_id="GHSA-unknown-0001",
        package=OsvPackage(name="unlisted-package", version="9.9.9", ecosystem="PyPI"),
        summary="advisory for a package not present in the lockfile",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
    )
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[
            OsvVulnerabilityAnalyzer(client_factory=lambda cfg: FakeClient(vulnerabilities=[vuln]))
        ],
    ).scan(repo)
    assert report.findings[0].location is None
    assert "did not publish a severity rating" in report.findings[0].explanation


def test_client_factory_receives_config(tmp_path: Path) -> None:
    repo = _pinned_python_repo(tmp_path)
    seen: list[ScanConfig] = []

    def factory(config: ScanConfig) -> FakeClient:
        seen.append(config)
        return FakeClient()

    ScanEngine(
        config=ScanConfig(enable_network_checks=True, network_timeout_seconds=3.0),
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=factory)],
    ).scan(repo)
    assert seen
    assert seen[0].network_timeout_seconds == 3.0


def test_analyze_without_coordinates_reports_message(tmp_path: Path) -> None:
    repo = tmp_path / "empty"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    context = __import__(
        "repolens.discovery", fromlist=["discover_repository"]
    ).discover_repository(repo, ScanConfig())
    analyzer = OsvVulnerabilityAnalyzer(client_factory=lambda cfg: FakeClient())
    assert analyzer.analyze(context, ScanConfig(enable_network_checks=True)) == []
    assert "No locked package versions" in (analyzer.completion_message() or "")


def test_package_cap_is_reported_as_partial_coverage(tmp_path: Path) -> None:
    """Packages beyond max_osv_packages are unchecked, so the run must not look complete."""
    repo = _pinned_python_repo(tmp_path)
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\nurllib3==2.2.1\nidna==3.7\n", encoding="utf-8"
    )
    client = FakeClient()
    analyzer = OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client)

    from repolens.discovery import discover_repository

    context = discover_repository(repo, ScanConfig())
    findings = analyzer.analyze(context, ScanConfig(enable_network_checks=True, max_osv_packages=1))

    assert findings == []
    assert len(client.received) == 1
    assert analyzer.coverage_partial() is True
    message = analyzer.completion_message() or ""
    assert "1 of 3 locked package version(s)" in message
    assert "max_osv_packages" in message
    assert "not checked" in message


def test_package_cap_not_flagged_when_every_package_fits(tmp_path: Path) -> None:
    repo = _pinned_python_repo(tmp_path)
    client = FakeClient()
    analyzer = OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client)

    from repolens.discovery import discover_repository

    context = discover_repository(repo, ScanConfig())
    analyzer.analyze(context, ScanConfig(enable_network_checks=True))

    assert analyzer.coverage_partial() is False
    assert "not checked" not in (analyzer.completion_message() or "")


def test_package_cap_makes_the_scan_incomplete_end_to_end(tmp_path: Path) -> None:
    """Regression: a vulnerability past the 300-package cap used to yield exit code 0."""
    from repolens.cli import EXIT_OPERATIONAL, determine_exit_code
    from repolens.reporting import evaluate

    repo = _pinned_python_repo(tmp_path)
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\nurllib3==2.2.1\nidna==3.7\n", encoding="utf-8"
    )
    client = FakeClient()
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True, max_osv_packages=1),
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client)],
    ).scan(repo)

    outcome = report.analyzer_outcomes[0]
    assert outcome.status == AnalyzerStatus.COMPLETED
    assert outcome.coverage_truncated is True
    assert evaluate(report).is_incomplete is True
    assert determine_exit_code(report) == EXIT_OPERATIONAL


def test_findings_cap_marks_reporting_failure_not_partial_file_coverage(tmp_path: Path) -> None:
    """Omitted findings are incomplete even when all requested packages were queried."""
    repo = _pinned_python_repo(tmp_path)
    vulnerabilities = [
        OsvVulnerability(
            vuln_id=f"GHSA-test-{index:04d}",
            package=OsvPackage(name="requests", version="2.31.0", ecosystem="PyPI"),
            summary="Advisory",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
        )
        for index in range(3)
    ]
    client = FakeClient(vulnerabilities=vulnerabilities)
    analyzer = OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client)

    from repolens.discovery import discover_repository

    context = discover_repository(repo, ScanConfig())
    findings = analyzer.analyze(
        context, ScanConfig(enable_network_checks=True, max_findings_per_analyzer=2)
    )

    assert len(findings) == 2
    assert analyzer.coverage_partial() is False
    assert "additional findings were omitted" in (analyzer.reporting_failure() or "")


def test_network_failure_after_start_marks_coverage_incomplete(tmp_path: Path) -> None:
    """Regression: `--network-checks` that fails mid-flight must not look like a clean run."""
    from repolens.cli import EXIT_OPERATIONAL, determine_exit_code
    from repolens.reporting import RenderOptions, evaluate, render_report

    repo = _pinned_python_repo(tmp_path)
    client = FakeClient(error=OsvNetworkError("OSV.dev is unreachable from this environment."))
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client)],
    ).scan(repo)

    outcome = report.analyzer_outcomes[0]
    # The status stays UNAVAILABLE (Stage 2 contract); the new flag carries the difference.
    assert outcome.status == AnalyzerStatus.UNAVAILABLE
    assert outcome.coverage_incomplete is True

    verdict = evaluate(report)
    assert verdict.is_incomplete is True
    assert [o.analyzer_name for o in verdict.aborted_checks] == ["osv-dependency-check"]
    # Not described as a missing optional tool.
    assert verdict.unavailable_analyzers == ()

    assert determine_exit_code(report) == EXIT_OPERATIONAL

    output = render_report(
        report, options=RenderOptions(color=False), exit_code=determine_exit_code(report)
    )
    assert "started but could not complete" in output
    assert "osv-dependency-check" in output
    assert "optional tools are not installed" not in output
    assert "exit code 3" in output


def test_network_failure_with_findings_still_exits_one(tmp_path: Path) -> None:
    """Exit-code precedence: qualifying findings outrank incomplete coverage."""
    from repolens.cli import EXIT_FINDINGS, determine_exit_code
    from repolens.reporting import evaluate as evaluate_incomplete

    repo = _pinned_python_repo(tmp_path)
    (repo / "LICENSE").unlink()  # guarantees a MEDIUM structure finding
    client = FakeClient(error=OsvNetworkError("offline"))
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[
            StructureAnalyzer(),
            OsvVulnerabilityAnalyzer(client_factory=lambda cfg: client),
        ],
    ).scan(repo)

    assert report.findings, "fixture must report at least one finding"
    assert evaluate_incomplete(report).is_incomplete is True
    assert determine_exit_code(report) == EXIT_FINDINGS
