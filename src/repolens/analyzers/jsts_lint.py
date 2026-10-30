"""Biome-first JavaScript/TypeScript static analysis adapter.

RepoLens only uses a Biome executable that is already installed on the host. It never
runs ``npm install``/``pnpm install`` and never executes repository scripts. Because
repository configuration can enable plugins, custom paths, or remote schemas, Biome is
invoked with a RepoLens-generated configuration file instead of the project's own
``biome.json``; the presence of project configuration is reported in the outcome message.
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
    select_config_files,
    select_source_files,
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
    Finding,
    FindingLocation,
    FindingSource,
    Severity,
    SourceKind,
)

_JS_TS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
_BIOME_CONFIG_NAMES = frozenset({"biome.json", "biome.jsonc"})

# Hardened, self-contained configuration written into the disposable tool workspace.
# `recommended` is used (rather than the Biome 2 `preset` equivalent) so the same file
# works with both Biome 1.x and 2.x.
_BIOME_CONFIG: dict[str, object] = {
    "linter": {"enabled": True, "rules": {"recommended": True}},
    "vcs": {"enabled": False, "clientKind": "git", "useIgnoreFile": False},
    "files": {"ignoreUnknown": True},
}

_SEVERITY_MAP: dict[str, Severity] = {
    "error": Severity.MEDIUM,
    "warning": Severity.LOW,
    "information": Severity.INFO,
    "info": Severity.INFO,
    "hint": Severity.INFO,
}

_CONFIDENCE_MAP: dict[str, Confidence] = {
    "error": Confidence.HIGH,
    "warning": Confidence.MEDIUM,
    "information": Confidence.MEDIUM,
    "info": Confidence.MEDIUM,
    "hint": Confidence.LOW,
}


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


def _category_for(rule: str) -> Category:
    parts = rule.split("/")
    if len(parts) >= 2 and parts[1] == "security":
        return Category.SECURITY
    return Category.CODE_QUALITY


class BiomeAnalyzer(Analyzer):
    """Lint JavaScript/TypeScript with an already-installed Biome executable."""

    def __init__(self) -> None:
        self._message: str | None = None
        self._coverage_partial = False

    @property
    def name(self) -> str:
        return "biome-jsts-lint"

    def is_applicable(self, context: RepositoryContext) -> bool:
        return bool(select_source_files(context, _JS_TS_SUFFIXES, limit=1))

    def check_availability(self) -> AnalyzerAvailability:
        return analyzer_availability("biome")

    def completion_message(self) -> str | None:
        return self._message

    def coverage_partial(self) -> bool:
        return self._coverage_partial

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        self._reset_reporting()
        self._message = None
        self._coverage_partial = False
        files, capped = select_source_files_with_status(
            context, _JS_TS_SUFFIXES, config.max_tool_files
        )
        self._coverage_partial = capped
        if not files:
            self._message = "No eligible JavaScript/TypeScript source files were found for Biome."
            return []

        tool_version_str = tool_version("biome")
        findings: list[Finding] = []
        empty_result: tuple[list[Finding], str | None] = ([], None)
        truncated = False
        processed_files = 0
        skipped_files = 0

        with tool_workspace() as workspace:
            config_path = workspace / "repolens-biome.json"
            config_path.write_text(json.dumps(_BIOME_CONFIG), encoding="utf-8")

            for batch in iter_batches(files, config.tool_batch_size):
                processed_files += len(batch)
                paths = absolute_paths(context.canonical_root, batch)
                if not paths:
                    continue
                result = run_tool(
                    "biome",
                    [
                        "lint",
                        "--reporter=json",
                        f"--max-diagnostics={config.max_findings_per_analyzer}",
                        "--no-errors-on-unmatched",
                        f"--config-path={config_path}",
                        *paths,
                    ],
                    cwd=workspace,
                    timeout_seconds=config.subprocess_timeout_seconds,
                    max_output_bytes=config.subprocess_max_output_bytes,
                )
                if result.returncode not in (0, 1):
                    raise AnalyzerExecutionError(
                        "Biome exited with status "
                        f"{result.returncode}: {result.redacted_stderr() or '<no stderr>'}"
                    )

                parsed, output_failure = parse_diagnostic_stdout(
                    "Biome",
                    result,
                    lambda stdout: self._parse_diagnostics(
                        stdout, context, workspace, tool_version_str
                    ),
                    fallback=empty_result,
                )
                batch_findings, summary_failure = parsed
                if output_failure:
                    self._mark_reporting_failure(output_failure)
                if summary_failure:
                    self._mark_reporting_failure(summary_failure)
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
                f"Biome only analyzed {processed_files} file(s): the max_tool_files limit "
                f"({config.max_tool_files}) was reached, so other files were not linted."
            )
        if truncated:
            parts.append(
                f"Biome findings truncated to {config.max_findings_per_analyzer}; "
                f"{processed_files} file(s) analyzed."
            )
        if skipped_files:
            parts.append(
                f"Biome reached the finding limit; {skipped_files} eligible file(s) "
                "in later batches were not analyzed."
            )
        elif not truncated:
            parts.append(f"Biome analyzed {processed_files} JavaScript/TypeScript file(s).")
        config_note = untrusted_config_message(context, _BIOME_CONFIG_NAMES)
        if config_note:
            parts.append(config_note)
        elif select_config_files(context, _BIOME_CONFIG_NAMES):
            parts.append("Project Biome configuration detected but not loaded.")
        self._message = " ".join(parts)
        return findings

    def _parse_diagnostics(
        self,
        stdout: str,
        context: RepositoryContext,
        cwd: Path,
        tool_version_str: str | None,
    ) -> tuple[list[Finding], str | None]:
        if not stdout.strip():
            return [], None

        payload = self._load_json(stdout)
        summary = _as_mapping(payload.get("summary"))
        summary_failure: str | None = None
        if "diagnosticsNotPrinted" in summary:
            not_printed = summary["diagnosticsNotPrinted"]
            if not isinstance(not_printed, int) or isinstance(not_printed, bool) or not_printed < 0:
                summary_failure = "Biome returned an invalid diagnosticsNotPrinted count."
            elif not_printed > 0:
                summary_failure = "Biome did not print all diagnostics (diagnosticsNotPrinted > 0)."
        diagnostics = payload.get("diagnostics", [])
        if not isinstance(diagnostics, list):
            raise AnalyzerExecutionError("Biome JSON output did not contain a diagnostics list.")

        findings: list[Finding] = []
        for raw in diagnostics:
            item = _as_mapping(raw)
            rule = _as_str(item.get("category"))
            message = _as_str(item.get("message"))
            location = _as_mapping(item.get("location"))
            raw_path = _as_str(location.get("path"))
            if not rule or not message or not raw_path:
                continue

            rel_path = repository_relative_path(raw_path, root=context.canonical_root, cwd=cwd)
            if rel_path is None:
                continue

            start = _as_mapping(location.get("start"))
            end = _as_mapping(location.get("end"))
            start_line = _as_positive_int(start.get("line"))
            end_line = _as_positive_int(end.get("line"))
            column = _as_positive_int(start.get("column"))
            if start_line is not None and end_line is not None and end_line < start_line:
                end_line = None

            severity_key = (_as_str(item.get("severity")) or "warning").lower()
            severity = _SEVERITY_MAP.get(severity_key, Severity.LOW)
            confidence = _CONFIDENCE_MAP.get(severity_key, Confidence.MEDIUM)
            category = _category_for(rule)
            rule_short = rule.rsplit("/", 1)[-1]

            findings.append(
                Finding(
                    rule_id=f"BIOME-{rule_short}"[:128],
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    title=_truncate(f"Biome {rule_short} · {message}", 240),
                    location=FindingLocation(
                        path=rel_path,
                        start_line=start_line,
                        end_line=end_line,
                        column=column,
                    ),
                    evidence=message,
                    explanation=_truncate(
                        f"{message} Reported by Biome rule `{rule}` ({severity_key} severity).",
                        4000,
                    ),
                    recommendation=_truncate(
                        f"Resolve `{rule}` in {rel_path}, or suppress it explicitly with a "
                        "`// biome-ignore` comment and a written justification.",
                        4000,
                    ),
                    verification=(f"Run `biome lint {rel_path}` and confirm `{rule}` is resolved."),
                    source=FindingSource(
                        kind=SourceKind.DETERMINISTIC,
                        tool="biome",
                        tool_version=tool_version_str,
                        rule_url=f"https://biomejs.dev/linter/rules/{_kebab_case(rule_short)}/",
                    ),
                )
            )
        return findings, summary_failure

    @staticmethod
    def _load_json(stdout: str) -> dict[str, Any]:
        try:
            parsed: object = json.loads(stdout)
        except json.JSONDecodeError:
            parsed = None
            for line in reversed(stdout.splitlines()):
                candidate = line.strip()
                if not candidate.startswith("{"):
                    continue
                try:
                    parsed = json.loads(candidate)
                except json.JSONDecodeError:
                    continue
                break
        if not isinstance(parsed, dict):
            raise AnalyzerExecutionError("Biome returned malformed JSON output.")
        return cast("dict[str, Any]", parsed)


def _kebab_case(rule_name: str) -> str:
    """Convert a Biome rule name (camelCase) into its documentation URL slug."""
    output: list[str] = []
    for index, char in enumerate(rule_name):
        if char.isupper() and index > 0:
            output.append("-")
        output.append(char.lower())
    return "".join(output)


__all__ = ["BiomeAnalyzer"]
