"""Unit tests for the Biome JavaScript/TypeScript analyzer adapter."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from repolens.analyzers.base import AnalyzerExecutionError
from repolens.analyzers.jsts_lint import BiomeAnalyzer
from repolens.config import ScanConfig
from repolens.discovery import discover_repository
from repolens.subprocess_runner import SubprocessResult


class RunRecorder:
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
        config_snapshot = None
        for arg in args:
            if arg.startswith("--config-path="):
                config_path = Path(arg.split("=", 1)[1])
                if config_path.is_file():
                    config_snapshot = json.loads(config_path.read_text(encoding="utf-8"))
        self.calls.append(
            {
                "name": name,
                "args": list(args),
                "cwd": cwd,
                "timeout_seconds": timeout_seconds,
                "max_output_bytes": max_output_bytes,
                "config_snapshot": config_snapshot,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _result(stdout: str, returncode: int = 1) -> SubprocessResult:
    return SubprocessResult(
        argv=("biome",),
        returncode=returncode,
        stdout=stdout,
        stderr="",
        duration_ms=1.0,
    )


def _biome_payload(path: str, **overrides: Any) -> dict[str, Any]:
    diagnostic: dict[str, Any] = {
        "severity": "error",
        "message": "This is an unexpected use of the debugger statement.",
        "category": "lint/suspicious/noDebugger",
        "location": {
            "path": path,
            "start": {"line": 3, "column": 3},
            "end": {"line": 3, "column": 12},
        },
        "advices": [],
    }
    diagnostic.update(overrides)
    return {"summary": {"errors": 1}, "diagnostics": [diagnostic], "command": "lint"}


def test_biome_maps_diagnostics_to_findings(
    make_jsts_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_jsts_repo()
    target = repo / "src" / "index.ts"
    recorder = RunRecorder([_result(json.dumps(_biome_payload(str(target))))])
    monkeypatch.setattr("repolens.analyzers.jsts_lint.run_tool", recorder)

    analyzer = BiomeAnalyzer()
    findings = analyzer.analyze(discover_repository(repo, ScanConfig()), ScanConfig())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "BIOME-noDebugger"
    assert finding.severity.value == "medium"
    assert finding.category.value == "code_quality"
    assert finding.location is not None
    assert finding.location.path == "src/index.ts"
    assert finding.location.start_line == 3
    assert finding.source.tool == "biome"
    assert finding.source.rule_url == "https://biomejs.dev/linter/rules/no-debugger/"

    call = recorder.calls[0]
    assert call["name"] == "biome"
    assert call["args"][0] == "lint"
    assert "--reporter=json" in call["args"]
    assert "--no-errors-on-unmatched" in call["args"]
    assert call["cwd"] != repo.resolve()


def test_biome_uses_hardened_config_not_repository_config(
    make_jsts_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_jsts_repo()
    (repo / "biome.json").write_text(
        json.dumps(
            {
                "linter": {"rules": {"recommended": False}},
                "plugins": ["https://evil.example.com/plugin.grit"],
            }
        ),
        encoding="utf-8",
    )
    recorder = RunRecorder([_result(json.dumps({"diagnostics": []}), returncode=0)])
    monkeypatch.setattr("repolens.analyzers.jsts_lint.run_tool", recorder)

    analyzer = BiomeAnalyzer()
    findings = analyzer.analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    assert findings == []

    call = recorder.calls[0]
    config_arg = next(arg for arg in call["args"] if arg.startswith("--config-path="))
    config_path = Path(config_arg.split("=", 1)[1])
    assert config_path != repo / "biome.json"
    assert config_path.parent == call["cwd"]
    written = call["config_snapshot"]
    assert written is not None
    assert written["linter"]["rules"]["recommended"] is True
    assert written["vcs"]["enabled"] is False
    assert "plugins" not in written

    message = analyzer.completion_message() or ""
    assert "biome.json" in message
    assert "not loaded" in message


def test_biome_severity_and_category_mapping(
    make_jsts_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_jsts_repo()
    target = repo / "src" / "index.ts"
    payload = {
        "diagnostics": [
            _biome_payload(
                str(target),
                severity="warning",
                message="Variable is unused.",
                category="lint/correctness/noUnusedVariables",
            )["diagnostics"][0],
            _biome_payload(
                str(target),
                severity="information",
                message="Avoid dangerouslySetInnerHTML.",
                category="lint/security/noDangerouslySetInnerHtml",
            )["diagnostics"][0],
            _biome_payload(str(target), severity="hint")["diagnostics"][0],
        ]
    }
    monkeypatch.setattr(
        "repolens.analyzers.jsts_lint.run_tool",
        RunRecorder([_result(json.dumps(payload))]),
    )

    findings = BiomeAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["BIOME-noUnusedVariables"].severity.value == "low"
    assert by_rule["BIOME-noDangerouslySetInnerHtml"].category.value == "security"
    assert by_rule["BIOME-noDangerouslySetInnerHtml"].severity.value == "info"
    assert by_rule["BIOME-noDebugger"].severity.value == "info"


def test_biome_tolerates_leading_log_noise(
    make_jsts_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_jsts_repo()
    target = repo / "src" / "index.ts"
    noisy = (
        "deprecated config notice\n" + json.dumps(_biome_payload(str(target))) + "\nlint finished\n"
    )
    monkeypatch.setattr(
        "repolens.analyzers.jsts_lint.run_tool",
        RunRecorder([_result(noisy)]),
    )
    findings = BiomeAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    assert len(findings) == 1


def test_biome_malformed_output_raises(
    make_jsts_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_jsts_repo()
    monkeypatch.setattr(
        "repolens.analyzers.jsts_lint.run_tool",
        RunRecorder([_result("definitely not json")]),
    )
    with pytest.raises(AnalyzerExecutionError, match="malformed JSON"):
        BiomeAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())


def test_biome_failure_exit_code_raises(
    make_jsts_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_jsts_repo()
    monkeypatch.setattr(
        "repolens.analyzers.jsts_lint.run_tool",
        RunRecorder([_result("", returncode=2)]),
    )
    with pytest.raises(AnalyzerExecutionError, match="exited with status 2"):
        BiomeAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())


def test_biome_not_applicable_without_jsts_sources(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    context = discover_repository(repo, ScanConfig())
    analyzer = BiomeAnalyzer()
    assert analyzer.is_applicable(context) is False
    assert analyzer.analyze(context, ScanConfig()) == []


def test_biome_resolves_paths_reported_relative_to_cwd(
    make_jsts_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_jsts_repo()
    recorder = RunRecorder(
        [_result(json.dumps(_biome_payload("../" + repo.name + "/src/index.ts")))]
    )
    monkeypatch.setattr("repolens.analyzers.jsts_lint.run_tool", recorder)

    findings = BiomeAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    # The reported relative path escapes the disposable workspace and cannot be mapped.
    assert findings == []


def test_biome_skips_diagnostics_without_usable_location(
    make_jsts_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_jsts_repo()
    payload = {
        "diagnostics": [
            {"severity": "error", "message": "no category", "location": {"path": "src/index.ts"}},
            {"severity": "error", "category": "lint/x", "location": {"path": "src/index.ts"}},
            {"severity": "error", "category": "lint/x", "message": "m"},
            {
                "severity": "error",
                "category": "lint/x",
                "message": "m",
                "location": {"path": "/etc/passwd"},
            },
        ]
    }
    monkeypatch.setattr(
        "repolens.analyzers.jsts_lint.run_tool",
        RunRecorder([_result(json.dumps(payload))]),
    )
    assert BiomeAnalyzer().analyze(discover_repository(repo, ScanConfig()), ScanConfig()) == []


def test_biome_analyzer_message_reports_analyzed_files(
    make_jsts_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_jsts_repo()
    monkeypatch.setattr(
        "repolens.analyzers.jsts_lint.run_tool",
        RunRecorder([_result(json.dumps({"diagnostics": []}), returncode=0)]),
    )
    analyzer = BiomeAnalyzer()
    analyzer.analyze(discover_repository(repo, ScanConfig()), ScanConfig())
    message = analyzer.completion_message() or ""
    assert "Biome analyzed" in message
    assert "JavaScript/TypeScript" in message
