"""Unit tests for the Ruff and Bandit analyzer adapters (external tools mocked)."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from repolens.analyzers.base import (
    AnalyzerExecutionError,
    AnalyzerTimeoutError,
)
from repolens.analyzers.python_lint import BanditAnalyzer, RuffAnalyzer
from repolens.config import ScanConfig
from repolens.discovery import discover_repository
from repolens.subprocess_runner import SubprocessResult


class RunRecorder:
    """Records argv/cwd for tool invocations and returns scripted results."""

    def __init__(self, responses: Sequence[SubprocessResult | Exception]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        name: str,
        args: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> SubprocessResult:
        self.calls.append(
            {
                "name": name,
                "args": list(args),
                "cwd": cwd,
                "timeout_seconds": timeout_seconds,
                "max_output_bytes": max_output_bytes,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _result(stdout: str, returncode: int = 1, stderr: str = "") -> SubprocessResult:
    return SubprocessResult(
        argv=("tool",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=1.0,
    )


def _ruff_diagnostic(path: Path, code: str = "F401", **overrides: Any) -> dict[str, Any]:
    diagnostic: dict[str, Any] = {
        "code": code,
        "message": "`os` imported but unused",
        "filename": str(path),
        "location": {"row": 1, "column": 8},
        "end_location": {"row": 1, "column": 10},
        "name": "unused-import",
        "url": "https://docs.astral.sh/ruff/rules/unused-import",
    }
    diagnostic.update(overrides)
    return diagnostic


def test_ruff_analyzer_maps_diagnostics_to_findings(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    context = discover_repository(repo, ScanConfig())
    target = repo / "src" / "sample" / "core.py"
    recorder = RunRecorder([_result(json.dumps([_ruff_diagnostic(target)]))])
    monkeypatch.setattr("repolens.analyzers.python_lint.run_tool", recorder)

    findings = RuffAnalyzer().analyze(context, ScanConfig())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "RUFF-F401"
    assert finding.severity.value == "low"
    assert finding.category.value == "code_quality"
    assert finding.location is not None
    assert finding.location.path == "src/sample/core.py"
    assert finding.location.start_line == 1
    assert finding.location.end_line == 1
    assert finding.source.tool == "ruff"
    assert finding.source.rule_url == "https://docs.astral.sh/ruff/rules/unused-import"
    assert "imported but unused" in (finding.evidence or "")

    call = recorder.calls[0]
    assert call["name"] == "ruff"
    assert "--isolated" in call["args"]
    assert "--no-cache" in call["args"]
    assert "--output-format=json" in call["args"]
    assert call["args"][call["args"].index("--select") + 1] == "E4,E7,E9,F,B"
    assert call["cwd"] != repo.resolve()
    assert all(";" not in arg and "|" not in arg and "&&" not in arg for arg in call["args"])


def test_ruff_syntax_errors_are_high_severity(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    context = discover_repository(repo, ScanConfig())
    target = repo / "src" / "sample" / "core.py"
    diagnostic = _ruff_diagnostic(
        target,
        code="invalid-syntax",
        name="invalid-syntax",
        message="Expected an expression",
        url=None,
    )
    recorder = RunRecorder([_result(json.dumps([diagnostic]), returncode=1)])
    monkeypatch.setattr("repolens.analyzers.python_lint.run_tool", recorder)

    findings = RuffAnalyzer().analyze(context, ScanConfig())
    assert findings[0].severity.value == "high"
    assert findings[0].rule_id == "RUFF-invalid-syntax"
    assert "cannot be imported" in findings[0].recommendation
    assert findings[0].source.rule_url == ("https://docs.astral.sh/ruff/rules/invalid-syntax")


def test_ruff_reports_are_capped_and_flagged(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    target = repo / "src" / "sample" / "core.py"
    diagnostics = [_ruff_diagnostic(target) for _ in range(3)]
    recorder = RunRecorder([_result(json.dumps(diagnostics))])
    monkeypatch.setattr("repolens.analyzers.python_lint.run_tool", recorder)

    analyzer = RuffAnalyzer()
    findings = analyzer.analyze(
        discover_repository(repo, ScanConfig()),
        ScanConfig(max_findings_per_analyzer=2),
    )
    assert len(findings) == 2
    assert "truncated" in (analyzer.completion_message() or "")


def test_ruff_malformed_output_raises(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    context = discover_repository(repo, ScanConfig())
    monkeypatch.setattr(
        "repolens.analyzers.python_lint.run_tool",
        RunRecorder([_result("not-json", returncode=1)]),
    )
    with pytest.raises(AnalyzerExecutionError, match="malformed JSON"):
        RuffAnalyzer().analyze(context, ScanConfig())


def test_ruff_tool_failure_raises_execution_error(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    context = discover_repository(repo, ScanConfig())
    token = "ghp_" + "A" * 30
    monkeypatch.setattr(
        "repolens.analyzers.python_lint.run_tool",
        RunRecorder([_result("", returncode=2, stderr=f"crash with {token}")]),
    )
    with pytest.raises(AnalyzerExecutionError) as exc_info:
        RuffAnalyzer().analyze(context, ScanConfig())
    assert token not in str(exc_info.value)


def test_ruff_timeout_propagates(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    context = discover_repository(repo, ScanConfig())
    monkeypatch.setattr(
        "repolens.analyzers.python_lint.run_tool",
        RunRecorder([AnalyzerTimeoutError("ruff exceeded the 30s analysis timeout")]),
    )
    with pytest.raises(AnalyzerTimeoutError):
        RuffAnalyzer().analyze(context, ScanConfig())


def test_ruff_drops_findings_outside_repository(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = make_python_repo()
    outside = tmp_path / "elsewhere.py"
    outside.write_text("import os\n", encoding="utf-8")
    recorder = RunRecorder([_result(json.dumps([_ruff_diagnostic(outside)]))])
    monkeypatch.setattr("repolens.analyzers.python_lint.run_tool", recorder)

    findings = RuffAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    assert findings == []


def test_bandit_analyzer_maps_results_to_findings(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    target = repo / "src" / "sample" / "core.py"
    payload = {
        "results": [
            {
                "test_id": "B307",
                "test_name": "blacklist",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "filename": str(target),
                "line_number": 5,
                "issue_text": "Use of possibly insecure function - consider ast.literal_eval.",
                "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
                "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html",
            }
        ],
        "errors": [],
    }
    recorder = RunRecorder([_result(json.dumps(payload), returncode=1)])
    monkeypatch.setattr("repolens.analyzers.python_lint.run_tool", recorder)

    analyzer = BanditAnalyzer()
    findings = analyzer.analyze(discover_repository(repo, ScanConfig()), ScanConfig())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "BANDIT-B307"
    assert finding.severity.value == "medium"
    assert finding.confidence.value == "high"
    assert finding.category.value == "security"
    assert finding.location is not None
    assert finding.location.path == "src/sample/core.py"
    assert finding.location.start_line == 5
    assert "CWE-78" in finding.explanation
    assert finding.source.tool == "bandit"

    call = recorder.calls[0]
    assert "--skip" in call["args"]
    skipped = call["args"][call["args"].index("--skip") + 1]
    assert "B101" in skipped
    assert "B603" in skipped
    assert call["cwd"] != repo.resolve()


def test_bandit_reports_unknown_severity_as_low(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    payload = {
        "results": [
            {
                "test_id": "B999",
                "test_name": "custom",
                "issue_severity": "NONSENSE",
                "issue_confidence": "NONSENSE",
                "filename": str(repo / "src" / "sample" / "core.py"),
                "line_number": 1,
                "issue_text": "Unusual finding",
            }
        ]
    }
    monkeypatch.setattr(
        "repolens.analyzers.python_lint.run_tool",
        RunRecorder([_result(json.dumps(payload))]),
    )
    findings = BanditAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    assert findings[0].severity.value == "low"
    assert findings[0].confidence.value == "low"


def test_bandit_malformed_output_raises(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    monkeypatch.setattr(
        "repolens.analyzers.python_lint.run_tool",
        RunRecorder([_result("{bad json")]),
    )
    with pytest.raises(AnalyzerExecutionError):
        BanditAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())


def test_bandit_notes_untrusted_project_configuration(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    (repo / ".bandit").write_text("skips: ['*']\n", encoding="utf-8")
    monkeypatch.setattr(
        "repolens.analyzers.python_lint.run_tool",
        RunRecorder([_result(json.dumps({"results": []}), returncode=0)]),
    )
    analyzer = BanditAnalyzer()
    analyzer.analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    assert ".bandit" in (analyzer.completion_message() or "")
    assert "not loaded" in (analyzer.completion_message() or "")


def test_bandit_empty_output_with_clean_exit_is_not_an_error(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    monkeypatch.setattr(
        "repolens.analyzers.python_lint.run_tool",
        RunRecorder([_result("", returncode=0)]),
    )
    assert BanditAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig()) == []


def test_ruff_evidence_is_redacted(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    token = "ghp_" + "B" * 32
    diagnostic = _ruff_diagnostic(
        repo / "src" / "sample" / "core.py",
        message=f"Hardcoded token {token} detected",
    )
    monkeypatch.setattr(
        "repolens.analyzers.python_lint.run_tool",
        RunRecorder([_result(json.dumps([diagnostic]))]),
    )
    findings = RuffAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    assert token not in (findings[0].evidence or "")
    assert "REDACTED" in (findings[0].evidence or "")


def test_ruff_skips_malformed_diagnostics(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    payload = [
        {"code": "F401"},
        {"message": "missing code", "filename": "x.py"},
        {"code": "F401", "message": "ok", "filename": 42},
        {
            "code": "F401",
            "message": "no location block",
            "filename": str(repo / "src" / "sample" / "core.py"),
        },
    ]
    monkeypatch.setattr(
        "repolens.analyzers.python_lint.run_tool",
        RunRecorder([_result(json.dumps(payload))]),
    )
    findings = RuffAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.start_line is None


def test_analyzers_report_when_no_eligible_files_remain(
    make_python_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_python_repo()
    (repo / ".gitignore").write_text("src/\ntests/\n__pycache__/\n.venv/\n.env\n", encoding="utf-8")
    context = discover_repository(repo, ScanConfig())

    recorder = RunRecorder([])
    monkeypatch.setattr("repolens.analyzers.python_lint.run_tool", recorder)

    ruff = RuffAnalyzer()
    assert ruff.analyze(context, ScanConfig()) == []
    assert "No eligible Python source files" in (ruff.completion_message() or "")

    bandit = BanditAnalyzer()
    assert bandit.analyze(context, ScanConfig()) == []
    assert "No eligible Python source files" in (bandit.completion_message() or "")
    assert recorder.calls == []
