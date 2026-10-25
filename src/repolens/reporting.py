"""Deterministic terminal rendering and result evaluation for RepoLens scans.

Rendering is a pure transformation of a :class:`ScanReport` into text, which keeps the
CLI thin, makes the output unit-testable without invoking any analyzer, and guarantees
that nothing beyond the already-redacted report models reaches a terminal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from repolens.models import AnalyzerOutcome, AnalyzerStatus, Finding, ScanReport, Severity

_MAX_MESSAGE_CHARS: Final = 108
_MAX_ANALYZER_MESSAGE_CHARS: Final = 88
_MAX_PATH_CHARS: Final = 40
_MAX_RULE_CHARS: Final = 24
_SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
_INCOMPLETE_STATUSES: Final[frozenset[AnalyzerStatus]] = frozenset(
    {AnalyzerStatus.FAILED, AnalyzerStatus.TIMED_OUT}
)

_RESET: Final = "\x1b[0m"
_BOLD: Final = "\x1b[1m"
_DIM: Final = "\x1b[2m"
_RED: Final = "\x1b[91m"
_YELLOW: Final = "\x1b[93m"
_GREEN: Final = "\x1b[92m"
_CYAN: Final = "\x1b[96m"

_SEVERITY_STYLES: Final[dict[Severity, str]] = {
    Severity.CRITICAL: f"{_BOLD}{_RED}",
    Severity.HIGH: _RED,
    Severity.MEDIUM: _YELLOW,
    Severity.LOW: _CYAN,
    Severity.INFO: _DIM,
}

_STATUS_STYLES: Final[dict[AnalyzerStatus, str]] = {
    AnalyzerStatus.COMPLETED: _DIM,
    AnalyzerStatus.SKIPPED: _DIM,
    AnalyzerStatus.UNAVAILABLE: _YELLOW,
    AnalyzerStatus.TIMED_OUT: _RED,
    AnalyzerStatus.FAILED: _RED,
}

_EMPTY_CELL: Final = "-"


@dataclass(frozen=True, slots=True)
class RenderOptions:
    """Presentation settings for terminal output."""

    color: bool = False
    min_severity: Severity = Severity.INFO
    max_findings: int = 50


@dataclass(frozen=True, slots=True)
class _Painter:
    """Applies ANSI styles only when color output is enabled."""

    color: bool

    def __call__(self, text: str, style: str) -> str:
        if not self.color or not style:
            return text
        return f"{style}{text}{_RESET}"


@dataclass(frozen=True, slots=True)
class ScanVerdict:
    """Outcome-relevant view of a report: what was detected and how complete it is."""

    threshold: Severity
    total_findings: int
    findings_at_or_above: tuple[Finding, ...]
    incomplete_analyzers: tuple[AnalyzerOutcome, ...]
    unavailable_analyzers: tuple[AnalyzerOutcome, ...]

    @property
    def has_findings(self) -> bool:
        """True when at least one finding meets the configured severity threshold."""
        return bool(self.findings_at_or_above)

    @property
    def hidden_findings(self) -> int:
        """Number of findings suppressed by the severity threshold."""
        return self.total_findings - len(self.findings_at_or_above)

    @property
    def is_incomplete(self) -> bool:
        """True when an analyzer failed or timed out, so coverage is incomplete."""
        return bool(self.incomplete_analyzers)

    @property
    def is_clean(self) -> bool:
        """True only when the scan completed and nothing met the threshold."""
        return not self.has_findings and not self.is_incomplete


def evaluate(report: ScanReport, min_severity: Severity = Severity.INFO) -> ScanVerdict:
    """Compute the exit-relevant verdict for ``report`` at ``min_severity``."""
    return ScanVerdict(
        threshold=min_severity,
        total_findings=len(report.findings),
        findings_at_or_above=tuple(
            finding for finding in report.findings if finding.severity.rank >= min_severity.rank
        ),
        incomplete_analyzers=tuple(
            outcome
            for outcome in report.analyzer_outcomes
            if outcome.status in _INCOMPLETE_STATUSES
        ),
        unavailable_analyzers=tuple(
            outcome
            for outcome in report.analyzer_outcomes
            if outcome.status is AnalyzerStatus.UNAVAILABLE
        ),
    )


def format_bytes(size_bytes: int) -> str:
    """Format a byte count using binary units."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    value = float(size_bytes)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        value /= 1024.0
        if value < 1024.0:
            return f"{value:.1f} {unit}"
    return f"{value:.1f} PiB"


def render_report(
    report: ScanReport,
    *,
    options: RenderOptions | None = None,
    target_path: str | None = None,
    exit_code: int | None = None,
) -> str:
    """Render ``report`` as printable terminal text (without a trailing newline)."""
    opts = options or RenderOptions()
    paint = _Painter(opts.color)
    verdict = evaluate(report, opts.min_severity)

    lines: list[str] = [
        f"{paint(f'RepoLens {report.repolens_version}', _BOLD)}"
        f"{paint(f' · {report.repository_name}', _DIM)}"
    ]
    if target_path:
        lines.append(paint(f"Target: {target_path}", _DIM))
    lines.append(_render_discovery(report, paint))
    lines.append("")
    lines.extend(_render_findings(verdict, opts, paint))
    lines.append("")
    lines.extend(_render_analyzers(report, paint))
    lines.append("")
    lines.extend(_render_summary(verdict, opts, paint, exit_code))

    notes = _render_notes(report, verdict, opts, paint)
    if notes:
        lines.append("")
        lines.extend(notes)
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------------------


def _render_discovery(report: ScanReport, paint: _Painter) -> str:
    discovery = report.discovery
    parts = [
        f"Scanned {discovery.total_files_scanned} file(s)",
        format_bytes(discovery.total_bytes_scanned),
        f"in {report.duration_ms:.0f} ms",
    ]
    if discovery.detected_languages:
        languages = ", ".join(language.value for language in discovery.detected_languages)
        parts.append(f"languages: {languages}")
    return paint(" · ".join(parts), _DIM)


def _render_findings(verdict: ScanVerdict, opts: RenderOptions, paint: _Painter) -> list[str]:
    threshold = opts.min_severity.value
    if verdict.total_findings == 0:
        return [paint("Findings", _BOLD), f"  {paint('No findings detected.', _GREEN)}"]

    if not verdict.has_findings:
        return [
            f"{paint('Findings', _BOLD)} — none at or above '{threshold}' severity "
            f"({verdict.total_findings} below threshold)",
            f"  {paint('No findings detected at this threshold.', _GREEN)}",
        ]

    shown = verdict.findings_at_or_above[: opts.max_findings]
    label = f"{len(verdict.findings_at_or_above)} at or above '{threshold}' severity"
    if verdict.hidden_findings:
        label += f", {verdict.hidden_findings} below threshold"
    lines = [f"{paint('Findings', _BOLD)} — {label}"]

    headers = ("SEVERITY", "RULE", "LOCATION", "MESSAGE")
    rows = [
        (
            finding.severity.value.upper(),
            _clip(finding.rule_id, _MAX_RULE_CHARS),
            _clip(_format_location(finding), _MAX_PATH_CHARS),
            _clip(finding.title, _MAX_MESSAGE_CHARS),
        )
        for finding in shown
    ]
    widths = [max(len(cell[index]) for cell in [*rows, headers]) for index in range(len(headers))]

    lines.append(_row(headers, widths))
    for finding, row in zip(shown, rows, strict=True):
        cells = [
            paint(cell.ljust(width), _SEVERITY_STYLES[finding.severity])
            if index == 0
            else cell.ljust(width)
            for index, (cell, width) in enumerate(zip(row, widths, strict=True))
        ]
        lines.append(("  " + "  ".join(cells)).rstrip())

    if len(verdict.findings_at_or_above) > len(shown):
        hidden = len(verdict.findings_at_or_above) - len(shown)
        lines.append(
            paint(
                f"  ... {hidden} more finding(s) not shown (use --max-findings to raise the limit)",
                _DIM,
            )
        )
    if verdict.hidden_findings:
        lines.append(
            paint(
                f"  {verdict.hidden_findings} finding(s) below the '{threshold}' threshold are "
                "hidden (use --min-severity info to show them)",
                _DIM,
            )
        )
    return lines


def _render_analyzers(report: ScanReport, paint: _Painter) -> list[str]:
    if not report.analyzer_outcomes:
        return [paint("Analyzers", _BOLD), "  No analyzers were registered."]

    rows: list[tuple[str, str, str, AnalyzerStatus]] = []
    for outcome in report.analyzer_outcomes:
        detail = outcome.message or ""
        if outcome.status is AnalyzerStatus.COMPLETED:
            detail = f"{outcome.findings_count} finding(s) in {outcome.duration_ms:.0f} ms"
        rows.append(
            (
                outcome.status.value,
                _clip(outcome.analyzer_name, 30),
                _clip(detail, _MAX_ANALYZER_MESSAGE_CHARS),
                outcome.status,
            )
        )

    headers = ("STATUS", "ANALYZER", "DETAIL")
    widths = [max(len(cell[index]) for cell in [*rows, headers]) for index in range(len(headers))]

    lines = [paint("Analyzers", _BOLD), _row(headers, widths)]
    for row in rows:
        cells = [
            paint(row[0].ljust(widths[0]), _STATUS_STYLES[row[3]]),
            row[1].ljust(widths[1]),
            row[2].ljust(widths[2]),
        ]
        lines.append(("  " + "  ".join(cells)).rstrip())
    return lines


def _render_summary(
    verdict: ScanVerdict, opts: RenderOptions, paint: _Painter, exit_code: int | None
) -> list[str]:
    counts = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in verdict.findings_at_or_above:
        counts[finding.severity] += 1

    cells: list[str] = []
    for severity in _SEVERITY_ORDER:
        count = counts[severity]
        label = f"{severity.value} {count}"
        cells.append(paint(label, _SEVERITY_STYLES[severity]) if count else label)

    threshold = opts.min_severity.value
    detected = len(verdict.findings_at_or_above)
    if verdict.has_findings and verdict.is_incomplete:
        result = (
            f"{detected} finding(s) detected at or above '{threshold}' severity, but the scan "
            "is incomplete"
        )
        result_style = _RED
    elif verdict.has_findings:
        result = f"{detected} finding(s) detected at or above '{threshold}' severity"
        result_style = _RED if opts.min_severity.rank >= Severity.MEDIUM.rank else _YELLOW
    elif verdict.is_incomplete:
        result = f"scan incomplete — no confirmed findings at or above '{threshold}' severity"
        result_style = _RED
    else:
        result = f"no findings at or above '{threshold}' severity"
        result_style = _GREEN

    suffix = f" (exit code {exit_code})" if exit_code is not None else ""
    return [
        paint("Summary", _BOLD),
        "  " + " · ".join(cells),
        f"  {paint('Result:', _BOLD)} {paint(result + suffix, result_style)}",
    ]


def _render_notes(
    report: ScanReport, verdict: ScanVerdict, opts: RenderOptions, paint: _Painter
) -> list[str]:
    notes: list[str] = []
    truncation = _truncation_note(report, paint)
    if truncation:
        notes.append(truncation)
    if verdict.incomplete_analyzers:
        names = ", ".join(outcome.analyzer_name for outcome in verdict.incomplete_analyzers)
        notes.append(
            paint(
                f"Warning: {len(verdict.incomplete_analyzers)} analyzer(s) failed or timed out, "
                f"so results are incomplete: {names}",
                _RED,
            )
        )
    if verdict.unavailable_analyzers:
        names = ", ".join(outcome.analyzer_name for outcome in verdict.unavailable_analyzers)
        notes.append(
            paint(
                f"Note: {len(verdict.unavailable_analyzers)} analyzer(s) unavailable because "
                f"optional tools are not installed: {names}",
                _YELLOW,
            )
        )
    if opts.min_severity is not Severity.INFO:
        notes.append(
            paint(
                f"Note: only findings at or above '{opts.min_severity.value}' severity affect "
                "the result; every severity is counted above.",
                _DIM,
            )
        )
    return notes


def _truncation_note(report: ScanReport, paint: _Painter) -> str | None:
    """Warn when discovery stopped early, so a clean result cannot look complete."""
    discovery = report.discovery
    limits: list[str] = []
    if discovery.truncated_by_file_limit:
        limits.append("maximum file count")
    if discovery.truncated_by_byte_limit:
        limits.append("maximum total bytes")
    if not limits:
        return None
    return paint(
        "Warning: discovery stopped early after reaching the "
        + " and ".join(limits)
        + " limit; results may be incomplete.",
        _RED,
    )


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _row(cells: tuple[str, ...], widths: list[int]) -> str:
    return (
        "  " + "  ".join(cell.ljust(width) for cell, width in zip(cells, widths, strict=True))
    ).rstrip()


def _clip(text: str, limit: int) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3].rstrip() + "..."


def _format_location(finding: Finding) -> str:
    location = finding.location
    if location is None:
        return _EMPTY_CELL
    if location.start_line is not None:
        return f"{location.path}:{location.start_line}"
    return location.path


__all__ = [
    "RenderOptions",
    "ScanVerdict",
    "evaluate",
    "format_bytes",
    "render_report",
]
