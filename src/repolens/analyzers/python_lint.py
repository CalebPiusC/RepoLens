"""Ruff and Bandit adapters converting external Python tool output into ``Finding`` objects.

Both analyzers require the tool to be installed already; RepoLens never installs tools and
never executes repository code. Repository tool configuration is ignored: Ruff runs with
``--isolated``, and Bandit runs from a disposable working directory.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from repolens.analyzers.base import Analyzer, AnalyzerAvailability, AnalyzerExecutionError
from repolens.analyzers.tooling import (
    absolute_paths,
    analyzer_availability,
    iter_batches,
    parse_diagnostic_stdout,
    repository_relative_path,
    run_tool,
    select_source_files_with_status,
    tool_version,
    tool_workspace,
    untrusted_config_message,
)
from repolens.config import ScanConfig
from repolens.discovery import RepositoryContext
from repolens.models import (
    Category,
    Confidence,
    DetectedLanguage,
    Finding,
    FindingLocation,
    FindingSource,
    Severity,
    SourceKind,
)

_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})

# Focused, low-noise rule selection:
#   E4/E7/E9 -> import and syntax errors,  F -> Pyflakes correctness,  B -> flake8-bugbear.
_RUFF_SELECT = "E4,E7,E9,F,B"

# Bandit checks that are intentionally skipped because they are dominated by false
# positives in ordinary application code and test suites (documented in the README).
_BANDIT_SKIP: tuple[str, ...] = (
    "B101",  # assert_used (ubiquitous in tests)
    "B105",  # hardcoded_password_string (fixtures, examples, docs)
    "B106",  # hardcoded_password_funcarg
    "B110",  # try_except_pass
    "B112",  # try_except_continue
    "B311",  # pseudo-random generators (non-cryptographic uses are common)
    "B404",  # subprocess module import
    "B603",  # subprocess call without shell (expected for tooling projects)
    "B607",  # partial executable path (paired with B603 usage)
)

_BANDIT_SEVERITY: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.LOW,
}

_BANDIT_CONFIDENCE: dict[str, Confidence] = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
    "UNDEFINED": Confidence.LOW,
}

_RUFF_DOCS_BASE = "https://docs.astral.sh/ruff/rules"


def _as_mapping(value: object) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _as_positive_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    return None


def _truncate(text: str, limit: int) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3].rstrip() + "..."


def _ruff_severity(code: str) -> Severity:
    if code == "invalid-syntax" or code.startswith("E9"):
        return Severity.HIGH
    if code.startswith("F8"):
        return Severity.MEDIUM
    if code.startswith("F"):
        return Severity.LOW
    if code.startswith("B"):
        return Severity.MEDIUM
    return Severity.LOW


def _ruff_confidence(code: str) -> Confidence:
    if code == "invalid-syntax" or code.startswith("E9"):
        return Confidence.HIGH
    if code.startswith("F"):
        return Confidence.HIGH
    return Confidence.MEDIUM


def _ruff_recommendation(code: str, rule_name: str, rel_path: str, row: int | None) -> str:
    location = f"{rel_path}:{row}" if row else rel_path
    if code == "invalid-syntax":
        return f"Fix the Python syntax error at {location}; the file cannot be imported."
    return (
        f"Resolve the {rule_name} (`{code}`) diagnostic at {location}, or add a documented "
        f"`# noqa: {code}` comment when the behavior is intentional."
    )


class RuffAnalyzer(Analyzer):
    """Run Ruff for Python lint, syntax, and code-quality diagnostics."""

    def __init__(self) -> None:
        self._message: str | None = None
        self._coverage_partial = False

    @property
    def name(self) -> str:
        return "ruff-python-lint"

    def is_applicable(self, context: RepositoryContext) -> bool:
        return DetectedLanguage.PYTHON in context.detected_languages

    def check_availability(self) -> AnalyzerAvailability:
        return analyzer_availability("ruff")

    def completion_message(self) -> str | None:
        return self._message

    def coverage_partial(self) -> bool:
        return self._coverage_partial

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        self._reset_reporting()
        self._message = None
        self._coverage_partial = False
        files, capped = select_source_files_with_status(
            context, _PYTHON_SUFFIXES, config.max_tool_files
        )
        self._coverage_partial = capped
        if not files:
            self._message = "No eligible Python source files were found for Ruff analysis."
            return []

        tool_version_str = tool_version("ruff")
        findings: list[Finding] = []
        empty_findings: list[Finding] = []
        truncated = False
        processed_files = 0
        skipped_files = 0

        with tool_workspace() as workspace:
            for batch in iter_batches(files, config.tool_batch_size):
                processed_files += len(batch)
                paths = absolute_paths(context.canonical_root, batch)
                if not paths:
                    continue
                result = run_tool(
                    "ruff",
                    [
                        "check",
                        "--isolated",
                        "--no-cache",
                        "--no-fix",
                        "--output-format=json",
                        "--select",
                        _RUFF_SELECT,
                        "--target-version",
                        "py311",
                        *paths,
                    ],
                    cwd=workspace,
                    timeout_seconds=config.subprocess_timeout_seconds,
                    max_output_bytes=config.subprocess_max_output_bytes,
                )
                if result.returncode not in (0, 1):
                    raise AnalyzerExecutionError(
                        "Ruff exited with status "
                        f"{result.returncode}: {result.redacted_stderr() or '<no stderr>'}"
                    )

                batch_findings, output_failure = parse_diagnostic_stdout(
                    "Ruff",
                    result,
                    lambda stdout: self._parse_diagnostics(
                        stdout, context, workspace, tool_version_str
                    ),
                    fallback=empty_findings,
                )
                if output_failure:
                    self._mark_reporting_failure(output_failure)
                findings.extend(batch_findings)
                truncated = len(findings) > config.max_findings_per_analyzer
                findings = self._limit_findings(findings, config.max_findings_per_analyzer)
                if len(findings) >= config.max_findings_per_analyzer:
                    skipped_files = len(files) - processed_files
                    self._coverage_partial |= skipped_files > 0
                    break

        parts: list[str] = []
        if capped:
            parts.append(
                f"Ruff only analyzed {processed_files} Python file(s): the max_tool_files limit "
                f"({config.max_tool_files}) was reached, so other files were not linted."
            )
        if truncated:
            parts.append(
                f"Ruff findings truncated to {config.max_findings_per_analyzer}; "
                f"{processed_files} file(s) analyzed."
            )
        if skipped_files:
            parts.append(
                f"Ruff reached the finding limit; {skipped_files} eligible file(s) "
                "in later batches were not analyzed."
            )
        if not parts:
            parts.append(f"Ruff analyzed {len(files)} Python file(s).")
        self._message = " ".join(parts)
        return findings

    def _parse_diagnostics(
        self,
        stdout: str,
        context: RepositoryContext,
        cwd: Path,
        tool_version_str: str | None,
    ) -> list[Finding]:
        if not stdout.strip():
            return []
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise AnalyzerExecutionError(f"Ruff returned malformed JSON output: {exc.msg}") from exc
        if not isinstance(parsed, list):
            raise AnalyzerExecutionError("Ruff JSON output was not a list of diagnostics.")

        findings: list[Finding] = []
        for raw in parsed:
            item = _as_mapping(raw)
            code = _as_str(item.get("code"))
            message = _as_str(item.get("message"))
            filename = _as_str(item.get("filename"))
            if not code or not message or not filename:
                continue

            rel_path = repository_relative_path(filename, root=context.canonical_root, cwd=cwd)
            if rel_path is None:
                continue

            location = _as_mapping(item.get("location"))
            row = _as_positive_int(location.get("row"))
            column = _as_positive_int(location.get("column"))
            end_row = _as_positive_int(_as_mapping(item.get("end_location")).get("row"))
            if row is not None and end_row is not None and end_row < row:
                end_row = None

            rule_name = _as_str(item.get("name")) or code
            rule_url = _as_str(item.get("url")) or f"{_RUFF_DOCS_BASE}/{rule_name}"

            findings.append(
                Finding(
                    rule_id=f"RUFF-{code}",
                    category=Category.CODE_QUALITY,
                    severity=_ruff_severity(code),
                    confidence=_ruff_confidence(code),
                    title=_truncate(f"Ruff {code} · {rule_name}", 240),
                    location=FindingLocation(
                        path=rel_path,
                        start_line=row,
                        end_line=end_row,
                        column=column,
                    ),
                    evidence=message,
                    explanation=_truncate(
                        f"{message}. Reported by Ruff rule {code} ({rule_name}).", 4000
                    ),
                    recommendation=_ruff_recommendation(code, rule_name, rel_path, row),
                    verification=(
                        f"Run `ruff check --isolated --select {code} {rel_path}` "
                        "and confirm the diagnostic is resolved."
                    ),
                    source=FindingSource(
                        kind=SourceKind.DETERMINISTIC,
                        tool="ruff",
                        tool_version=tool_version_str,
                        rule_url=rule_url if rule_url.startswith("https://") else None,
                    ),
                )
            )
        return findings


class BanditAnalyzer(Analyzer):
    """Run Bandit for common Python security anti-patterns."""

    def __init__(self) -> None:
        self._message: str | None = None
        self._coverage_partial = False

    @property
    def name(self) -> str:
        return "bandit-python-security"

    def is_applicable(self, context: RepositoryContext) -> bool:
        return DetectedLanguage.PYTHON in context.detected_languages

    def check_availability(self) -> AnalyzerAvailability:
        return analyzer_availability("bandit")

    def completion_message(self) -> str | None:
        return self._message

    def coverage_partial(self) -> bool:
        return self._coverage_partial

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        self._reset_reporting()
        self._message = None
        self._coverage_partial = False
        files, capped = select_source_files_with_status(
            context, _PYTHON_SUFFIXES, config.max_tool_files
        )
        self._coverage_partial = capped
        if not files:
            self._message = "No eligible Python source files were found for Bandit analysis."
            return []

        tool_version_str = tool_version("bandit")
        findings: list[Finding] = []
        empty_findings: list[Finding] = []
        truncated = False
        processed_files = 0
        skipped_files = 0

        with tool_workspace() as workspace:
            for batch in iter_batches(files, config.tool_batch_size):
                processed_files += len(batch)
                paths = absolute_paths(context.canonical_root, batch)
                if not paths:
                    continue
                result = run_tool(
                    "bandit",
                    ["-f", "json", "-q", "--skip", ",".join(_BANDIT_SKIP), *paths],
                    cwd=workspace,
                    timeout_seconds=config.subprocess_timeout_seconds,
                    max_output_bytes=config.subprocess_max_output_bytes,
                )
                if result.returncode not in (0, 1):
                    raise AnalyzerExecutionError(
                        "Bandit exited with status "
                        f"{result.returncode}: {result.redacted_stderr() or '<no stderr>'}"
                    )

                batch_findings, output_failure = parse_diagnostic_stdout(
                    "Bandit",
                    result,
                    lambda stdout: self._parse_results(
                        stdout, context, workspace, tool_version_str
                    ),
                    fallback=empty_findings,
                )
                if output_failure:
                    self._mark_reporting_failure(output_failure)
                findings.extend(batch_findings)
                truncated = len(findings) > config.max_findings_per_analyzer
                findings = self._limit_findings(findings, config.max_findings_per_analyzer)
                if len(findings) >= config.max_findings_per_analyzer:
                    skipped_files = len(files) - processed_files
                    self._coverage_partial |= skipped_files > 0
                    break

        parts: list[str] = []
        if capped:
            parts.append(
                f"Bandit only analyzed {processed_files} Python file(s): the max_tool_files limit "
                f"({config.max_tool_files}) was reached, so other files were not scanned."
            )
        if truncated:
            parts.append(
                f"Bandit findings truncated to {config.max_findings_per_analyzer}; "
                f"{processed_files} file(s) analyzed."
            )
        if skipped_files:
            parts.append(
                f"Bandit reached the finding limit; {skipped_files} eligible file(s) "
                "in later batches were not analyzed."
            )
        elif not truncated:
            parts.append(f"Bandit analyzed {processed_files} Python file(s).")
        config_note = untrusted_config_message(context, frozenset({".bandit", "bandit.yaml"}))
        if config_note:
            parts.append(config_note)
        self._message = " ".join(parts)
        return findings

    def _parse_results(
        self,
        stdout: str,
        context: RepositoryContext,
        cwd: Path,
        tool_version_str: str | None,
    ) -> list[Finding]:
        if not stdout.strip():
            return []
        try:
            parsed = _as_mapping(json.loads(stdout))
        except json.JSONDecodeError as exc:
            raise AnalyzerExecutionError(
                f"Bandit returned malformed JSON output: {exc.msg}"
            ) from exc

        results = parsed.get("results", [])
        if not isinstance(results, list):
            raise AnalyzerExecutionError("Bandit JSON output did not contain a results list.")

        findings: list[Finding] = []
        for raw in results:
            item = _as_mapping(raw)
            test_id = _as_str(item.get("test_id"))
            filename = _as_str(item.get("filename"))
            issue_text = _as_str(item.get("issue_text"))
            if not test_id or not filename or not issue_text:
                continue

            rel_path = repository_relative_path(filename, root=context.canonical_root, cwd=cwd)
            if rel_path is None:
                continue

            severity = _BANDIT_SEVERITY.get(
                (_as_str(item.get("issue_severity")) or "LOW").upper(), Severity.LOW
            )
            confidence = _BANDIT_CONFIDENCE.get(
                (_as_str(item.get("issue_confidence")) or "LOW").upper(), Confidence.LOW
            )
            line_number = _as_positive_int(item.get("line_number"))
            more_info = _as_str(item.get("more_info"))
            cwe_id = _as_positive_int(_as_mapping(item.get("issue_cwe")).get("id"))

            explanation_parts = [issue_text, f"Detected by Bandit check {test_id}."]
            if cwe_id is not None:
                explanation_parts.append(f"Associated CWE: CWE-{cwe_id}.")

            findings.append(
                Finding(
                    rule_id=f"BANDIT-{test_id}",
                    category=Category.SECURITY,
                    severity=severity,
                    confidence=confidence,
                    title=_truncate(f"Bandit {test_id} · {issue_text}", 240),
                    location=FindingLocation(path=rel_path, start_line=line_number),
                    evidence=issue_text,
                    explanation=_truncate(" ".join(explanation_parts), 4000),
                    recommendation=_truncate(
                        "Review this code path and replace the insecure construct with a safe "
                        "alternative. Use `# nosec` with a written justification only when the "
                        f"finding is a verified false positive. Reference: {more_info or test_id}",
                        4000,
                    ),
                    verification=(
                        f"Run `bandit -t {test_id} {rel_path}` and confirm the finding is "
                        "resolved or explicitly justified."
                    ),
                    source=FindingSource(
                        kind=SourceKind.DETERMINISTIC,
                        tool="bandit",
                        tool_version=tool_version_str,
                        rule_url=(
                            more_info
                            if more_info is not None and more_info.startswith("https://")
                            else None
                        ),
                    ),
                )
            )
        return findings


__all__ = ["BanditAnalyzer", "RuffAnalyzer"]
