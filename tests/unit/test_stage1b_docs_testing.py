"""Regressions for README link budgets and test-hygiene coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from repolens.analyzers.base import AnalyzerExecutionError
from repolens.analyzers.documentation import DocumentationAnalyzer
from repolens.analyzers.testing import TestingAnalyzer as HygieneAnalyzer
from repolens.cli import determine_exit_code
from repolens.config import ScanConfig
from repolens.discovery import RepositoryContext, discover_repository
from repolens.engine import ScanEngine
from repolens.exceptions import DiscoveryError
from repolens.json_output import build_json_document
from repolens.models import AnalyzerStatus, Severity
from repolens.reporting import RenderOptions, render_report

_LIMIT = 131_072


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _testing_repo(root: Path, files: int, text: str = "# no pytest import\n") -> None:
    _write(root, "pytest.ini", "[pytest]\n")
    for index in range(files):
        _write(root, f"tests/test_{index:02}.py", text)


def _run_hygiene(root: Path, analyzer: HygieneAnalyzer | None = None) -> HygieneAnalyzer:
    current = analyzer or HygieneAnalyzer()
    current.analyze(discover_repository(root, ScanConfig()), ScanConfig())
    return current


@pytest.mark.parametrize(("count", "failed"), [(499, False), (500, False), (501, True)])
def test_readme_eligible_link_budget_at_boundaries(
    tmp_path: Path, count: int, failed: bool
) -> None:
    _write(tmp_path, "LICENSE", "MIT\n")
    _write(tmp_path, "README.md", "[present](LICENSE)\n" * count)
    report = ScanEngine(analyzers=[DocumentationAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is (
        AnalyzerStatus.FAILED if failed else AnalyzerStatus.COMPLETED
    )
    assert not report.findings
    assert determine_exit_code(report) == (3 if failed else 0)
    if failed:
        assert not report.analyzer_outcomes[0].coverage_truncated
        assert "500-link limit" in (report.analyzer_outcomes[0].message or "")


def test_external_links_do_not_consume_the_eligible_budget(tmp_path: Path) -> None:
    _write(
        tmp_path, "README.md", "[external](https://example.com)\n" * 500 + "[broken](missing.md)\n"
    )
    report = ScanEngine(analyzers=[DocumentationAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.COMPLETED
    assert [f.rule_id for f in report.findings] == ["RL-DOC-003"]
    assert determine_exit_code(report) == 1


def test_only_ineligible_links_after_500_do_not_make_scan_incomplete(tmp_path: Path) -> None:
    _write(tmp_path, "LICENSE", "MIT\n")
    _write(
        tmp_path,
        "README.md",
        "[present](LICENSE)\n" * 500
        + "[site](https://example.com)\n[anchor](#section)\n[unsafe](../outside)\n",
    )
    report = ScanEngine(analyzers=[DocumentationAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.COMPLETED
    assert determine_exit_code(report) == 0


@pytest.mark.parametrize(
    ("tail", "failed"),
    [("", False), ("[external](https://example.com)\n", False), ("[present](LICENSE)\n", True)],
)
def test_ten_broken_links_only_fail_when_more_eligible_work_exists(
    tmp_path: Path, tail: str, failed: bool
) -> None:
    _write(tmp_path, "LICENSE", "MIT\n")
    _write(tmp_path, "README.md", "".join(f"[link](missing{i})\n" for i in range(10)) + tail)
    report = ScanEngine(analyzers=[DocumentationAnalyzer()]).scan(tmp_path)
    assert len(report.findings) == 10
    assert report.analyzer_outcomes[0].status is (
        AnalyzerStatus.FAILED if failed else AnalyzerStatus.COMPLETED
    )
    assert determine_exit_code(report, Severity.LOW) == 1
    assert determine_exit_code(report, Severity.CRITICAL) == (3 if failed else 0)
    document = build_json_document(report, exit_code=1, min_severity=Severity.LOW)
    assert document["schema_version"] == "1.1.0"
    assert document["result"]["status"] == ("findings_and_incomplete" if failed else "findings")
    if failed:
        output = render_report(report, options=RenderOptions(color=False), exit_code=1)
        assert "incomplete" in output.lower()
        assert "RL-DOC-003" in output


def test_readme_limit_reporting_reset_and_fail_fast(tmp_path: Path) -> None:
    _write(tmp_path, "LICENSE", "MIT\n")
    _write(tmp_path, "README.md", "[ok](LICENSE)\n" * 501)
    analyzer = DocumentationAnalyzer()
    first = ScanEngine(analyzers=[analyzer]).scan(tmp_path)
    assert first.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    with pytest.raises(AnalyzerExecutionError, match="500-link limit"):
        ScanEngine(config=ScanConfig(fail_fast=True), analyzers=[analyzer]).scan(tmp_path)
    _write(tmp_path, "README.md", "[ok](LICENSE)\n" * 500)
    second = ScanEngine(analyzers=[analyzer]).scan(tmp_path)
    assert second.analyzer_outcomes[0].status is AnalyzerStatus.COMPLETED
    assert analyzer.reporting_failure() is None


@pytest.mark.parametrize(("count", "failed"), [(19, False), (20, False), (21, True)])
def test_python_test_file_budget_at_boundaries(tmp_path: Path, count: int, failed: bool) -> None:
    _testing_repo(tmp_path, count)
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is (
        AnalyzerStatus.FAILED if failed else AnalyzerStatus.COMPLETED
    )
    assert not report.findings
    assert determine_exit_code(report) == (3 if failed else 0)


def test_ignored_and_oversized_test_files_do_not_count_as_eligible(tmp_path: Path) -> None:
    _testing_repo(tmp_path, 20)
    _write(tmp_path, ".gitignore", "ignored/\n")
    _write(tmp_path, "ignored/test_late.py", "import pytest\n")
    _write(tmp_path, "tests/test_oversized.py", "#" * 1025)
    report = ScanEngine(
        config=ScanConfig(max_file_size_bytes=1024), analyzers=[HygieneAnalyzer()]
    ).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.COMPLETED
    assert not report.findings


@pytest.mark.parametrize(("size", "failed"), [(131_071, False), (131_072, False), (131_073, True)])
def test_test_content_byte_budget_at_boundaries(tmp_path: Path, size: int, failed: bool) -> None:
    _testing_repo(tmp_path, 1, "#" * size)
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is (
        AnalyzerStatus.FAILED if failed else AnalyzerStatus.COMPLETED
    )
    assert not report.findings


def test_multibyte_text_is_limited_by_bytes_not_characters(tmp_path: Path) -> None:
    _testing_repo(tmp_path, 1, "#" + "é" * 65_536)  # 131,073 UTF-8 bytes
    analyzer = _run_hygiene(tmp_path)
    assert "byte-bounded" in (analyzer.reporting_failure() or "")


def test_import_crossing_byte_boundary_is_unknown_not_a_false_finding(tmp_path: Path) -> None:
    _testing_repo(tmp_path, 1, "#" * (_LIMIT - 8) + "\nimport pytest\n")
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert "RL-TEST-005" not in {f.rule_id for f in report.findings}
    assert determine_exit_code(report, Severity.CRITICAL) == 3


def test_truncated_identifier_is_not_mistaken_for_pytest(tmp_path: Path) -> None:
    _testing_repo(tmp_path, 1, "#" * (_LIMIT - len("import pytest") - 1) + "\nimport pytestx\n")
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert "RL-TEST-005" not in {f.rule_id for f in report.findings}


def test_prefix_read_is_byte_bounded_and_preserves_safe_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _testing_repo(tmp_path, 1, "#" * (_LIMIT + 1))
    limits: list[int] = []
    original = RepositoryContext._read_bytes

    def spy(context: RepositoryContext, path: str, limit: int) -> bytes:
        if path.endswith("test_00.py"):
            limits.append(limit)
        return original(context, path, limit)

    monkeypatch.setattr(RepositoryContext, "_read_bytes", spy)
    _run_hygiene(tmp_path)
    assert limits == [_LIMIT + 1]


@pytest.mark.parametrize("later_witness", [False, True])
def test_test_read_failure_only_matters_without_a_later_conclusive_witness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, later_witness: bool
) -> None:
    _testing_repo(tmp_path, 2)
    if later_witness:
        _write(tmp_path, "tests/test_01.py", "import pytest\n")
    original = RepositoryContext.read_text_prefix

    def fail_first(context: RepositoryContext, path: str, max_bytes: int) -> tuple[str, bool]:
        if path == "tests/test_00.py":
            raise DiscoveryError("unreadable")
        return original(context, path, max_bytes)

    monkeypatch.setattr(RepositoryContext, "read_text_prefix", fail_first)
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is (
        AnalyzerStatus.COMPLETED if later_witness else AnalyzerStatus.FAILED
    )
    assert ("RL-TEST-005" in {f.rule_id for f in report.findings}) is later_witness


def test_declared_pytest_and_first_import_witness_are_valid_early_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _testing_repo(tmp_path, 21)
    _write(tmp_path, "requirements.txt", "pytest>=8\n")
    original = RepositoryContext.read_text_prefix
    calls: list[str] = []

    def spy(context: RepositoryContext, path: str, max_bytes: int) -> tuple[str, bool]:
        calls.append(path)
        return original(context, path, max_bytes)

    monkeypatch.setattr(RepositoryContext, "read_text_prefix", spy)
    analyzer = HygieneAnalyzer()
    report = ScanEngine(analyzers=[analyzer]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.COMPLETED
    assert calls == []

    (tmp_path / "requirements.txt").unlink()
    _write(tmp_path, "tests/test_00.py", "import pytest\n")
    second = ScanEngine(analyzers=[analyzer]).scan(tmp_path)
    assert second.analyzer_outcomes[0].status is AnalyzerStatus.COMPLETED
    assert calls == ["tests/test_00.py"]
    assert [f.rule_id for f in second.findings] == ["RL-TEST-005"]
    assert analyzer.reporting_failure() is None


def test_unreadable_runner_config_suppresses_absence_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "tests/test_one.py", "# test\n")
    _write(tmp_path, "setup.cfg", "[tool:pytest]\n")
    original = RepositoryContext.read_text

    def fail_setup(context: RepositoryContext, path: str) -> str:
        if path == "setup.cfg":
            raise DiscoveryError("unreadable")
        return original(context, path)

    monkeypatch.setattr(RepositoryContext, "read_text", fail_setup)
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert "RL-TEST-003" not in {f.rule_id for f in report.findings}
    assert determine_exit_code(report, Severity.CRITICAL) == 3


def test_unreadable_coverage_config_suppresses_absence_but_retains_other_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _testing_repo(tmp_path, 1)
    _write(tmp_path, "requirements.txt", "pytest-cov>=5\n")
    _write(tmp_path, "vite.config.ts", "export default { coverage: {} };\n")
    original = RepositoryContext.read_text

    def fail_config(context: RepositoryContext, path: str) -> str:
        if path == "vite.config.ts":
            raise DiscoveryError("unreadable")
        return original(context, path)

    monkeypatch.setattr(RepositoryContext, "read_text", fail_config)
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert "RL-TEST-004" not in {f.rule_id for f in report.findings}
    assert "RL-TEST-002" in {f.rule_id for f in report.findings}
    assert determine_exit_code(report) == 1
    assert determine_exit_code(report, Severity.CRITICAL) == 3


def test_omitted_pytest_declaration_never_produces_false_import_finding(tmp_path: Path) -> None:
    _testing_repo(tmp_path, 1, "import pytest\n")
    for index in range(80):
        _write(tmp_path, f"inputs/{index:03}/requirements.txt", "")
    _write(tmp_path, "z/requirements.txt", "pytest==8.0.0\n")
    _write(tmp_path, "index.ts", "export const x = 1;\n")
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert "RL-TEST-005" not in {f.rule_id for f in report.findings}
    assert "RL-TEST-002" in {f.rule_id for f in report.findings}
    assert determine_exit_code(report) == 1


def test_hygiene_state_resets_after_sampling_gap(tmp_path: Path) -> None:
    _testing_repo(tmp_path, 21)
    analyzer = HygieneAnalyzer()
    report = ScanEngine(analyzers=[analyzer]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    (tmp_path / "tests/test_20.py").unlink()
    second = ScanEngine(analyzers=[analyzer]).scan(tmp_path)
    assert second.analyzer_outcomes[0].status is AnalyzerStatus.COMPLETED
    assert analyzer.reporting_failure() is None


def test_prefix_reads_preserve_discovery_security_and_size_limits(tmp_path: Path) -> None:
    from repolens.exceptions import (
        OversizedFileAccessError,
        PathSecurityError,
        SensitiveFileAccessError,
    )

    _write(tmp_path, "safe.py", "éX")
    _write(tmp_path, ".env", "SECRET=hidden")
    _write(tmp_path, "large.py", "x" * 1025)
    context = discover_repository(tmp_path, ScanConfig(max_file_size_bytes=1024))
    # A split UTF-8 character is held back rather than guessed.
    assert context.read_text_prefix("safe.py", 1) == ("", True)
    assert context.read_text_prefix("safe.py", 2) == ("é", True)
    assert context.read_text_prefix("safe.py", 3) == ("éX", False)
    with pytest.raises(SensitiveFileAccessError):
        context.read_text_prefix(".env", 10)
    with pytest.raises(OversizedFileAccessError):
        context.read_text_prefix("large.py", 10)
    with pytest.raises(PathSecurityError):
        context.read_text_prefix("../safe.py", 10)


def test_multibyte_identifier_crossing_the_boundary_is_not_a_witness(tmp_path: Path) -> None:
    _testing_repo(tmp_path, 1, "#" * (_LIMIT - len("import pytest") - 2) + "\nimport pytesté\n")
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert "RL-TEST-005" not in {f.rule_id for f in report.findings}


def test_known_coverage_witness_resolves_an_earlier_unreadable_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _testing_repo(tmp_path, 1)
    _write(tmp_path, "requirements.txt", "pytest-cov>=5\n")
    _write(tmp_path, "pyproject.toml", '[tool.coverage.run]\nsource = ["demo"]\n')
    _write(tmp_path, "vite.config.ts", "// coverage\n")
    original = RepositoryContext.read_text

    def fail_project(context: RepositoryContext, path: str) -> str:
        if path == "pyproject.toml":
            raise DiscoveryError("unreadable")
        return original(context, path)

    monkeypatch.setattr(RepositoryContext, "read_text", fail_project)
    analyzer = _run_hygiene(tmp_path)
    # A positive coverage witness is enough; there is no pytest import to require
    # proving whether the unavailable pyproject declares pytest.
    assert analyzer.reporting_failure() is None


def test_test_file_removed_after_discovery_is_not_mistaken_for_empty(tmp_path: Path) -> None:
    _testing_repo(tmp_path, 1)
    context = discover_repository(tmp_path, ScanConfig())
    (tmp_path / "tests/test_00.py").unlink()
    analyzer = HygieneAnalyzer()
    assert analyzer.analyze(context, ScanConfig()) == []
    assert "could not all be checked" in (analyzer.reporting_failure() or "")


def test_unsafe_json_runner_config_does_not_discard_confirmed_findings(tmp_path: Path) -> None:
    _write(tmp_path, "tests/test_one.js", "// test\n")
    _write(tmp_path, "src/core.py", "x = 1\n")
    _write(tmp_path, "package.json", '{"number": ' + "9" * 5000 + "}")
    report = ScanEngine(analyzers=[HygieneAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert "RL-TEST-003" not in {f.rule_id for f in report.findings}
    assert "RL-TEST-001" in {f.rule_id for f in report.findings}
