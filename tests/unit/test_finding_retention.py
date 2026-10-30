"""End-to-end regressions for bounded finding retention and diagnostic stdout."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from repolens.analyzers.advisories import OsvVulnerabilityAnalyzer
from repolens.analyzers.base import Analyzer, AnalyzerAvailability, AnalyzerExecutionError
from repolens.analyzers.dependencies import DependencyAnalyzer
from repolens.analyzers.documentation import DocumentationAnalyzer
from repolens.analyzers.jsts_lint import BiomeAnalyzer
from repolens.analyzers.python_lint import BanditAnalyzer, RuffAnalyzer
from repolens.analyzers.testing import TestingAnalyzer as HygieneAnalyzer
from repolens.cli import determine_exit_code, main
from repolens.config import ScanConfig
from repolens.engine import ScanEngine
from repolens.json_output import parse_json_document, render_json
from repolens.models import Confidence, ScanReport, Severity
from repolens.osv import OsvClient, OsvPackage, OsvVulnerability
from repolens.subprocess_runner import SubprocessResult


class _ToolRecorder:
    def __init__(self, responses: Sequence[SubprocessResult]) -> None:
        self.responses = list(responses)
        self.calls: list[Sequence[str]] = []

    def __call__(
        self,
        name: str,
        args: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> SubprocessResult:
        self.calls.append(args)
        return self.responses.pop(0)


def _tool_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str, count: int
) -> tuple[Path, Analyzer, list[Path], str]:
    root = tmp_path / "repo"
    root.mkdir()
    suffix = ".ts" if tool == "biome" else ".py"
    paths = [root / f"{index:02}{suffix}" for index in range(count)]
    for path in paths:
        path.write_text("x = 1\n", encoding="utf-8")

    analyzer: Analyzer
    if tool == "ruff":
        analyzer = RuffAnalyzer()
    elif tool == "bandit":
        analyzer = BanditAnalyzer()
    else:
        analyzer = BiomeAnalyzer()
    module = "repolens.analyzers.jsts_lint" if tool == "biome" else "repolens.analyzers.python_lint"
    monkeypatch.setattr(
        analyzer, "check_availability", lambda: AnalyzerAvailability(available=True)
    )
    monkeypatch.setattr(f"{module}.tool_version", lambda _name: "test")
    return root, analyzer, paths, module


def _tool_output(tool: str, path: Path, severities: Sequence[str]) -> str:
    if tool == "ruff":
        return json.dumps(
            [
                {
                    "code": "invalid-syntax" if severity == "high" else "F401",
                    "message": f"Issue {index}",
                    "filename": str(path),
                    "location": {"row": index + 1, "column": 1},
                }
                for index, severity in enumerate(severities)
            ]
        )
    if tool == "bandit":
        return json.dumps(
            {
                "results": [
                    {
                        "test_id": f"B{index:03}",
                        "filename": str(path),
                        "issue_text": f"Issue {index}",
                        "issue_severity": "HIGH" if severity == "high" else "LOW",
                        "issue_confidence": "HIGH",
                        "line_number": index + 1,
                    }
                    for index, severity in enumerate(severities)
                ]
            }
        )
    return json.dumps(
        {
            "summary": {"diagnosticsNotPrinted": 0},
            "diagnostics": [
                {
                    "category": f"lint/suspicious/rule{index}",
                    "message": f"Issue {index}",
                    "severity": "error" if severity == "high" else "warning",
                    "location": {"path": str(path), "start": {"line": index + 1}},
                }
                for index, severity in enumerate(severities)
            ],
        }
    )


def _result(
    stdout: str, *, stdout_truncated: bool = False, stderr_truncated: bool = False
) -> SubprocessResult:
    return SubprocessResult(
        argv=("tool",),
        returncode=1,
        stdout=stdout,
        stderr="logs" if stderr_truncated else "",
        duration_ms=1.0,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )


def _document(report: ScanReport, threshold: Severity) -> dict[str, Any]:
    exit_code = determine_exit_code(report, threshold)
    rendered = render_json(report, exit_code=exit_code, min_severity=threshold)
    parsed = parse_json_document(rendered, strict=True)
    assert parsed.report.schema_version == "1.1.0"
    assert parsed.result.exit_code == exit_code
    return json.loads(rendered)  # type: ignore[no-any-return]


@pytest.mark.parametrize("tool", ["ruff", "bandit", "biome"])
def test_cap_before_a_later_higher_severity_batch_is_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, tool, 2)
    recorder = _ToolRecorder(
        [
            _result(_tool_output(tool, paths[0], ["low"])),
            _result(_tool_output(tool, paths[1], ["high"])),
        ]
    )
    monkeypatch.setattr(f"{module}.run_tool", recorder)
    report = ScanEngine(
        config=ScanConfig(max_findings_per_analyzer=1, tool_batch_size=1), analyzers=[analyzer]
    ).scan(root)

    document = _document(report, Severity.MEDIUM)
    outcome = document["analyzer_outcomes"][0]
    assert len(recorder.calls) == 1  # the higher-severity second batch was not run
    assert outcome["status"] == "completed"
    assert outcome["coverage_truncated"] is True
    assert "later batches were not analyzed" in outcome["message"]
    assert [finding["severity"] for finding in document["findings"]] == ["low"]
    assert document["result"]["status"] == "incomplete"
    assert document["result"]["incomplete_reasons"] == ["analyzer_coverage_truncated"]
    assert document["result"]["exit_code"] == 3


@pytest.mark.parametrize("tool", ["ruff", "bandit", "biome"])
def test_exact_finding_cap_in_the_final_batch_is_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, tool, 2)
    recorder = _ToolRecorder(
        [_result(_tool_output(tool, paths[0], [])), _result(_tool_output(tool, paths[1], ["low"]))]
    )
    monkeypatch.setattr(f"{module}.run_tool", recorder)
    report = ScanEngine(
        config=ScanConfig(max_findings_per_analyzer=1, tool_batch_size=1), analyzers=[analyzer]
    ).scan(root)

    document = _document(report, Severity.MEDIUM)
    assert len(recorder.calls) == 2
    assert document["analyzer_outcomes"][0]["status"] == "completed"
    assert document["analyzer_outcomes"][0]["coverage_truncated"] is False
    assert document["result"]["status"] == "clean"
    assert document["result"]["is_complete"] is True
    assert document["result"]["exit_code"] == 0


@pytest.mark.parametrize("tool", ["ruff", "bandit", "biome"])
def test_final_batch_with_dropped_findings_is_failed_and_keeps_confirmed_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, tool, 1)
    monkeypatch.setattr(
        f"{module}.run_tool",
        _ToolRecorder([_result(_tool_output(tool, paths[0], ["low", "high"]))]),
    )
    report = ScanEngine(config=ScanConfig(max_findings_per_analyzer=1), analyzers=[analyzer]).scan(
        root
    )

    high_threshold = _document(report, Severity.MEDIUM)
    outcome = high_threshold["analyzer_outcomes"][0]
    assert outcome["status"] == "failed"
    assert outcome["findings_count"] == 1
    assert outcome["coverage_truncated"] is False
    assert "additional findings were omitted" in outcome["message"]
    assert [finding["severity"] for finding in high_threshold["findings"]] == ["low"]
    assert high_threshold["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert high_threshold["result"]["exit_code"] == 3

    low_threshold = _document(report, Severity.LOW)
    assert low_threshold["result"]["status"] == "findings_and_incomplete"
    assert low_threshold["result"]["has_findings"] is True
    assert low_threshold["result"]["is_complete"] is False
    assert low_threshold["result"]["exit_code"] == 1


@pytest.mark.parametrize("tool", ["ruff", "bandit", "biome"])
def test_truncated_malformed_later_stdout_preserves_previous_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, tool, 2)
    recorder = _ToolRecorder(
        [
            _result(_tool_output(tool, paths[0], ["low"])),
            _result('{"partial":', stdout_truncated=True),
        ]
    )
    monkeypatch.setattr(f"{module}.run_tool", recorder)
    report = ScanEngine(config=ScanConfig(tool_batch_size=1), analyzers=[analyzer]).scan(root)
    document = _document(report, Severity.MEDIUM)

    assert len(recorder.calls) == 2
    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert document["analyzer_outcomes"][0]["findings_count"] == 1
    assert "stdout was truncated" in document["analyzer_outcomes"][0]["message"]
    assert len(document["findings"]) == 1
    assert document["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert document["result"]["exit_code"] == 3


@pytest.mark.parametrize("tool", ["ruff", "bandit", "biome"])
def test_stderr_only_truncation_does_not_make_complete_stdout_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, tool, 1)
    result = _result(_tool_output(tool, paths[0], []), stderr_truncated=True)
    assert result.output_truncated is True
    assert result.stdout_truncated is False
    monkeypatch.setattr(f"{module}.run_tool", _ToolRecorder([result]))
    report = ScanEngine(analyzers=[analyzer]).scan(root)
    document = _document(report, Severity.HIGH)

    assert document["analyzer_outcomes"][0]["status"] == "completed"
    assert document["result"]["is_complete"] is True
    assert document["result"]["exit_code"] == 0


@pytest.mark.parametrize("tool", ["ruff", "bandit", "biome"])
def test_analyzer_reuse_clears_failure_and_file_coverage_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, tool, 2)
    recorder = _ToolRecorder(
        [
            _result(_tool_output(tool, paths[0], ["low", "high"])),
            _result(_tool_output(tool, paths[0], [])),
            _result(_tool_output(tool, paths[1], ["low"])),
        ]
    )
    monkeypatch.setattr(f"{module}.run_tool", recorder)
    engine = ScanEngine(
        config=ScanConfig(max_findings_per_analyzer=1, tool_batch_size=1), analyzers=[analyzer]
    )
    first = _document(engine.scan(root), Severity.MEDIUM)
    second = _document(engine.scan(root), Severity.MEDIUM)

    assert first["analyzer_outcomes"][0]["status"] == "failed"
    assert "later batches were not analyzed" in first["analyzer_outcomes"][0]["message"]
    assert first["result"]["exit_code"] == 3
    assert second["analyzer_outcomes"][0]["status"] == "completed"
    assert second["analyzer_outcomes"][0]["coverage_truncated"] is False
    assert second["result"]["is_complete"] is True
    assert second["result"]["exit_code"] == 0


def test_biome_diagnostics_not_printed_marks_reporting_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, "biome", 1)
    payload = json.loads(_tool_output("biome", paths[0], ["low"]))
    payload["summary"]["diagnosticsNotPrinted"] = 3
    monkeypatch.setattr(f"{module}.run_tool", _ToolRecorder([_result(json.dumps(payload))]))
    document = _document(ScanEngine(analyzers=[analyzer]).scan(root), Severity.MEDIUM)

    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert "diagnosticsNotPrinted" in document["analyzer_outcomes"][0]["message"]
    assert len(document["findings"]) == 1
    assert document["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert document["result"]["exit_code"] == 3


def test_biome_parseable_json_prefix_of_truncated_stdout_is_still_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, "biome", 1)
    stdout = "notice\n" + _tool_output("biome", paths[0], ["low"]) + '\n{"partial":'
    monkeypatch.setattr(
        f"{module}.run_tool", _ToolRecorder([_result(stdout, stdout_truncated=True)])
    )
    document = _document(ScanEngine(analyzers=[analyzer]).scan(root), Severity.LOW)

    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert document["analyzer_outcomes"][0]["findings_count"] == 1
    assert document["findings"][0]["rule_id"] == "BIOME-rule0"
    assert document["result"]["status"] == "findings_and_incomplete"
    assert document["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert document["result"]["exit_code"] == 1


def _dependency_repo(tmp_path: Path) -> Path:
    root = tmp_path / "dependency-repo"
    root.mkdir()
    (root / "bun.lockb").write_text("unsupported", encoding="utf-8")
    (root / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^19.0.0"}}), encoding="utf-8"
    )
    (root / "package-lock.json").write_text(
        json.dumps(
            {"lockfileVersion": 3, "packages": {"node_modules/react": {"version": "18.3.1"}}}
        ),
        encoding="utf-8",
    )
    return root


@pytest.mark.parametrize(
    ("threshold", "exit_code", "status"),
    [("medium", 3, "incomplete"), ("info", 1, "findings_and_incomplete")],
)
def test_cli_json_reports_dependency_finding_loss_and_exit_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    threshold: str,
    exit_code: int,
    status: str,
) -> None:
    root = _dependency_repo(tmp_path)

    def engine_factory(*, config: ScanConfig) -> ScanEngine:
        return ScanEngine(
            config=config.model_copy(update={"max_findings_per_analyzer": 1}),
            analyzers=[DependencyAnalyzer()],
        )

    monkeypatch.setattr("repolens.cli.ScanEngine", engine_factory)
    actual_exit = main(["scan", str(root), "--format", "json", "--min-severity", threshold])
    captured = capsys.readouterr()
    document = json.loads(captured.out)

    assert actual_exit == exit_code == document["result"]["exit_code"]
    assert captured.err == ""
    assert document["schema_version"] == "1.1.0"
    assert document["result"]["status"] == status
    assert document["result"]["is_complete"] is False
    assert document["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert document["analyzer_outcomes"][0]["coverage_truncated"] is False
    assert [finding["rule_id"] for finding in document["findings"]] == ["RL-DEP-007"]


def test_dependency_analyzer_reuse_and_exact_cap_are_complete(tmp_path: Path) -> None:
    root = _dependency_repo(tmp_path)
    analyzer = DependencyAnalyzer()
    engine = ScanEngine(config=ScanConfig(max_findings_per_analyzer=1), analyzers=[analyzer])
    assert _document(engine.scan(root), Severity.HIGH)["result"]["exit_code"] == 3
    (root / "package-lock.json").write_text(
        json.dumps(
            {"lockfileVersion": 3, "packages": {"node_modules/react": {"version": "19.0.0"}}}
        ),
        encoding="utf-8",
    )
    complete = _document(engine.scan(root), Severity.HIGH)
    assert complete["analyzer_outcomes"][0]["status"] == "completed"
    assert len(complete["findings"]) == 1
    assert complete["result"]["is_complete"] is True
    assert complete["result"]["exit_code"] == 0


@pytest.mark.parametrize("analyzer_kind", ["documentation", "testing"])
def test_other_capped_analyzers_report_dropped_findings_and_reset(
    tmp_path: Path, analyzer_kind: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    analyzer: Analyzer
    if analyzer_kind == "documentation":
        path = root / "README.md"
        path.write_text("[one](missing1)\n[two](missing2)\n", encoding="utf-8")
        analyzer = DocumentationAnalyzer()
    else:
        (root / "app.py").write_text("x = 1\n", encoding="utf-8")
        path = root / "app.js"
        path.write_text("const x = 1;\n", encoding="utf-8")
        analyzer = HygieneAnalyzer()
    engine = ScanEngine(config=ScanConfig(max_findings_per_analyzer=1), analyzers=[analyzer])
    first = _document(engine.scan(root), Severity.HIGH)
    assert first["analyzer_outcomes"][0]["status"] == "failed"
    assert first["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert len(first["findings"]) == 1
    assert first["result"]["exit_code"] == 3

    if analyzer_kind == "documentation":
        path.write_text("[one](missing1)\n", encoding="utf-8")
    else:
        path.unlink()
    second = _document(engine.scan(root), Severity.HIGH)
    assert second["analyzer_outcomes"][0]["status"] == "completed"
    assert second["result"]["is_complete"] is True
    assert len(second["findings"]) == 1
    assert second["result"]["exit_code"] == 0


@pytest.mark.parametrize(("links", "expected_status"), [(10, "completed"), (11, "failed")])
def test_readme_finding_limit_checks_whether_more_links_remain(
    tmp_path: Path, links: int, expected_status: str
) -> None:
    root = tmp_path / "docs-repo"
    root.mkdir()
    (root / "README.md").write_text(
        "".join(f"[link{index}](missing{index})\n" for index in range(links)), encoding="utf-8"
    )
    document = _document(ScanEngine(analyzers=[DocumentationAnalyzer()]).scan(root), Severity.HIGH)
    assert document["analyzer_outcomes"][0]["status"] == expected_status
    assert len(document["findings"]) == 10
    assert document["result"]["is_complete"] is (links == 10)
    assert document["result"]["exit_code"] == (0 if links == 10 else 3)


class _AdvisoryClient:
    def __init__(self, vulnerabilities: Sequence[OsvVulnerability]) -> None:
        self.vulnerabilities = list(vulnerabilities)

    def query(self, packages: Sequence[OsvPackage]) -> list[OsvVulnerability]:
        return self.vulnerabilities


def _vulnerability(name: str, severity: Severity) -> OsvVulnerability:
    return OsvVulnerability(
        vuln_id=name,
        package=OsvPackage(name="requests", version="2.31.0", ecosystem="PyPI"),
        summary="Advisory",
        severity=severity,
        confidence=Confidence.HIGH,
    )


def _osv_repo(tmp_path: Path) -> Path:
    root = tmp_path / "osv-repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    return root


def test_osv_analyzer_finding_cap_detects_unique_omissions_and_resets(tmp_path: Path) -> None:
    root = _osv_repo(tmp_path)
    low = _vulnerability("OSV-A", Severity.LOW)
    client = _AdvisoryClient([low, _vulnerability("OSV-Z", Severity.HIGH)])
    analyzer = OsvVulnerabilityAnalyzer(client_factory=lambda _cfg: client)
    engine = ScanEngine(
        config=ScanConfig(enable_network_checks=True, max_findings_per_analyzer=1),
        analyzers=[analyzer],
    )
    first = _document(engine.scan(root), Severity.HIGH)
    assert first["analyzer_outcomes"][0]["status"] == "failed"
    assert first["analyzer_outcomes"][0]["coverage_truncated"] is False
    assert first["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert first["result"]["exit_code"] == 3
    assert first["findings"][0]["severity"] == "low"

    # A duplicate after the cap is not another unique finding and must not signal loss.
    client.vulnerabilities = [low, low]
    second = _document(engine.scan(root), Severity.HIGH)
    assert second["analyzer_outcomes"][0]["status"] == "completed"
    assert second["result"]["is_complete"] is True
    assert second["result"]["exit_code"] == 0


class _OsvTransport:
    def __init__(self, ids: Sequence[str]) -> None:
        self.ids = list(ids)
        self.fetched: list[str] = []

    def post_json(self, path: str, payload: Mapping[str, object]) -> bytes:
        return json.dumps({"results": [{"vulns": [{"id": item} for item in self.ids]}]}).encode()

    def get_json(self, path: str) -> bytes:
        self.fetched.append(path)
        return json.dumps({"database_specific": {"severity": "LOW"}}).encode()


def test_osv_client_advisory_cap_marks_dropped_matches_and_respects_budget(tmp_path: Path) -> None:
    root = _osv_repo(tmp_path)
    transport = _OsvTransport(["OSV-A", "OSV-Z"])
    client = OsvClient(transport=transport, max_advisories=1)
    analyzer = OsvVulnerabilityAnalyzer(client_factory=lambda _cfg: client)
    engine = ScanEngine(
        config=ScanConfig(enable_network_checks=True, max_osv_advisories=1), analyzers=[analyzer]
    )
    first = _document(engine.scan(root), Severity.HIGH)
    assert len(transport.fetched) == 1
    assert first["analyzer_outcomes"][0]["status"] == "failed"
    assert "distinct advisories" in first["analyzer_outcomes"][0]["message"]
    assert first["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert first["result"]["exit_code"] == 3
    assert [finding["rule_id"] for finding in first["findings"]] == ["OSV-OSV-A"]

    transport.ids = ["OSV-A"]
    second = _document(engine.scan(root), Severity.HIGH)
    assert second["analyzer_outcomes"][0]["status"] == "completed"
    assert second["result"]["is_complete"] is True
    assert second["result"]["exit_code"] == 0
    assert client.advisories_truncated is False


def test_fail_fast_propagates_a_reporting_failure(tmp_path: Path) -> None:
    root = _dependency_repo(tmp_path)
    engine = ScanEngine(
        config=ScanConfig(max_findings_per_analyzer=1, fail_fast=True),
        analyzers=[DependencyAnalyzer()],
    )
    with pytest.raises(AnalyzerExecutionError, match="additional findings were omitted"):
        engine.scan(root)


@pytest.mark.parametrize("tool", ["ruff", "bandit", "biome"])
def test_parseable_truncated_stdout_is_never_a_clean_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, tool, 1)
    result = _result(_tool_output(tool, paths[0], []), stdout_truncated=True)
    monkeypatch.setattr(f"{module}.run_tool", _ToolRecorder([result]))
    document = _document(ScanEngine(analyzers=[analyzer]).scan(root), Severity.HIGH)
    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert document["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert document["result"]["exit_code"] == 3


def test_biome_real_runner_preserves_a_parseable_truncated_prefix(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "index.ts"
    target.write_text("const x = 1;\n", encoding="utf-8")
    payload = _tool_output("biome", target, ["low"])
    prefix = "notice\n" + payload + "\n{"
    script = f"sys.stdout.write({prefix!r} + 'x' * 8192)\n"
    install_fake_tool("biome", script, version="biome 2.0.0")
    report = ScanEngine(
        config=ScanConfig(subprocess_max_output_bytes=4096), analyzers=[BiomeAnalyzer()]
    ).scan(root)
    document = _document(report, Severity.LOW)
    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert "stdout was truncated" in document["analyzer_outcomes"][0]["message"]
    assert document["findings"][0]["rule_id"] == "BIOME-rule0"
    assert document["result"]["status"] == "findings_and_incomplete"
    assert document["result"]["exit_code"] == 1


@pytest.mark.parametrize("bad_count", ["1", -1, True, None])
def test_invalid_biome_omission_count_cannot_be_treated_as_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_count: object
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, "biome", 1)
    payload = json.loads(_tool_output("biome", paths[0], ["low"]))
    payload["summary"]["diagnosticsNotPrinted"] = bad_count
    monkeypatch.setattr(f"{module}.run_tool", _ToolRecorder([_result(json.dumps(payload))]))
    document = _document(ScanEngine(analyzers=[analyzer]).scan(root), Severity.HIGH)
    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert "invalid diagnosticsNotPrinted" in document["analyzer_outcomes"][0]["message"]
    assert len(document["findings"]) == 1
    assert document["result"]["exit_code"] == 3


def test_legacy_aggregate_truncation_flag_is_treated_conservatively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, "ruff", 1)
    result = SubprocessResult(
        argv=("ruff",),
        returncode=0,
        stdout=_tool_output("ruff", paths[0], []),
        stderr="",
        duration_ms=1.0,
        output_truncated=True,
    )
    monkeypatch.setattr(f"{module}.run_tool", _ToolRecorder([result]))
    document = _document(ScanEngine(analyzers=[analyzer]).scan(root), Severity.HIGH)
    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert document["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert document["result"]["exit_code"] == 3


def test_biome_unprinted_diagnostics_without_retained_findings_are_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, analyzer, _paths, module = _tool_repo(tmp_path, monkeypatch, "biome", 1)
    stdout = json.dumps({"summary": {"diagnosticsNotPrinted": 1}, "diagnostics": []})
    monkeypatch.setattr(f"{module}.run_tool", _ToolRecorder([_result(stdout)]))
    document = _document(ScanEngine(analyzers=[analyzer]).scan(root), Severity.HIGH)
    assert document["findings"] == []
    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert document["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert document["result"]["exit_code"] == 3


def test_reporting_failure_survives_long_tool_configuration_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, analyzer, paths, module = _tool_repo(tmp_path, monkeypatch, "biome", 2)
    recorder = _ToolRecorder([_result(_tool_output("biome", paths[0], ["low", "high"]))])
    monkeypatch.setattr(f"{module}.run_tool", recorder)
    monkeypatch.setattr(f"{module}.untrusted_config_message", lambda *_args: "x" * 2000)
    report = ScanEngine(
        config=ScanConfig(max_findings_per_analyzer=1, tool_batch_size=1), analyzers=[analyzer]
    ).scan(root)
    document = _document(report, Severity.MEDIUM)
    message = document["analyzer_outcomes"][0]["message"]
    assert document["analyzer_outcomes"][0]["status"] == "failed"
    assert "additional findings were omitted" in message
    assert "later batches were not analyzed" in message
    assert len(message) <= 500
    assert len(document["findings"]) == 1
    assert document["result"]["exit_code"] == 3
