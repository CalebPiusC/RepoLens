"""Self-contained HTML rendering of a :class:`~repolens.models.ScanReport`.

The module is a *renderer*: it reads the report the engine already produced and never scans,
evaluates, or invents data. Everything it shows comes from the report models plus the shared
:func:`repolens.reporting.evaluate` verdict and :func:`repolens.json_output.build_scan_result`
status, so the HTML report, the terminal report, and the JSON document always agree.

Design constraints, in order of importance:

* **Safe by construction.** Every repository-derived string (titles, paths, analyzer messages,
  descriptions) is passed through :func:`html.escape` before it reaches the document. Nothing is
  interpolated into a script or a CSS block, there is no ``<script>`` at all, and rule links are
  emitted only for ``http(s)`` URLs.
* **Self-contained.** One file, inline CSS, no JavaScript, no CDN, no fonts or images fetched
  over the network. It renders identically offline and from ``file://``.
* **Accessible.** Semantic landmarks and headings, a table of contents, real table headers, text
  labels alongside colour, visible focus styles, and a dark theme with high contrast.
* **Deterministic.** Except for the report's own ``scanned_at``/``duration_ms``, the same report
  always produces byte-identical HTML.
"""

from __future__ import annotations

import html
from typing import Final
from urllib.parse import urlsplit

from repolens.json_output import build_scan_result
from repolens.models import (
    AnalyzerOutcome,
    AnalyzerStatus,
    Finding,
    ScanReport,
    ScanResult,
    ScanStatus,
    Severity,
)
from repolens.reporting import format_bytes

_SEVERITY_LABELS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}

_SEVERITY_SUMMARY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_STATUS_LABELS: Final[dict[ScanStatus, tuple[str, str]]] = {
    ScanStatus.CLEAN: ("Clean scan", "No findings met the configured severity threshold."),
    ScanStatus.FINDINGS: ("Findings detected", "Findings met the configured severity threshold."),
    ScanStatus.INCOMPLETE: (
        "Scan incomplete",
        "No findings met the threshold, but coverage was incomplete.",
    ),
    ScanStatus.FINDINGS_AND_INCOMPLETE: (
        "Findings detected, scan incomplete",
        "Findings met the threshold and coverage was incomplete.",
    ),
}

_STYLE: Final = """
:root {
  color-scheme: dark;
  --bg: #0b0f16;
  --panel: #141a23;
  --panel-alt: #1b2330;
  --border: #263141;
  --text: #e6edf3;
  --muted: #9aa7b8;
  --accent: #6ea8fe;
  --clean: #3fb950;
  --critical: #ff6b6b;
  --high: #ff8f6b;
  --medium: #e3b341;
  --low: #6ea8fe;
  --info: #9aa7b8;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  padding: 2.5rem 1.25rem 4rem;
  background: var(--bg);
  color: var(--text);
  font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica,
    Arial, sans-serif;
}
.wrap { max-width: 1040px; margin: 0 auto; }
a { color: var(--accent); }
a:focus-visible, summary:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px;
}
.skip-link {
  position: absolute; left: -9999px; top: 0; background: var(--accent); color: #04101f;
  padding: 0.5rem 0.75rem; font-weight: 600; z-index: 10;
}
.skip-link:focus { left: 1rem; top: 1rem; }
header.page-header { border-bottom: 1px solid var(--border); padding-bottom: 1.25rem; }
.eyebrow {
  margin: 0 0 0.35rem; color: var(--muted); font-size: 0.8rem;
  letter-spacing: 0.08em; text-transform: uppercase;
}
h1 { margin: 0; font-size: clamp(1.6rem, 4vw, 2.3rem); line-height: 1.2; word-break: break-word; }
.subtitle { margin: 0.4rem 0 0; color: var(--muted); }
h2 { margin: 2.5rem 0 0.9rem; font-size: 1.15rem; letter-spacing: 0.01em; }
h3 { margin: 0 0 0.35rem; font-size: 1.02rem; line-height: 1.35; word-break: break-word; }
p { margin: 0.4rem 0; }
section { scroll-margin-top: 1rem; }
.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 12px; padding: 1.25rem;
}
.status-card { border-left: 4px solid var(--muted); }
.status-clean { border-left-color: var(--clean); }
.status-findings { border-left-color: var(--medium); }
.status-incomplete { border-left-color: var(--critical); }
.status-findings_and_incomplete { border-left-color: var(--critical); }
.status-label { margin: 0; font-size: 1.25rem; font-weight: 700; }
.status-detail { margin: 0.2rem 0 1rem; color: var(--muted); }
dl.grid {
  display: grid; gap: 0.9rem 1.5rem; margin: 0;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
}
dl.grid > div { min-width: 0; }
dt { color: var(--muted); font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase; }
dd { margin: 0.15rem 0 0; font-weight: 600; word-break: break-word; }
table { width: 100%; border-collapse: collapse; font-size: 0.94rem; }
caption { text-align: left; color: var(--muted); padding-bottom: 0.6rem; font-size: 0.85rem; }
th, td {
  text-align: left; padding: 0.55rem 0.7rem;
  border-bottom: 1px solid var(--border); vertical-align: top;
}
th { color: var(--muted); font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase; }
tbody tr:last-child td { border-bottom: none; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.bar {
  background: var(--panel-alt); border-radius: 999px; height: 8px;
  min-width: 80px; overflow: hidden;
}
.bar > span { display: block; height: 100%; border-radius: 999px; background: var(--accent); }
.sev-critical .bar > span { background: var(--critical); }
.sev-high .bar > span { background: var(--high); }
.sev-medium .bar > span { background: var(--medium); }
.sev-low .bar > span { background: var(--low); }
.sev-info .bar > span { background: var(--info); }
.badge {
  display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px;
  font-size: 0.75rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase;
  border: 1px solid currentColor;
}
.sev-critical .badge, .badge.sev-critical { color: var(--critical); }
.sev-high .badge, .badge.sev-high { color: var(--high); }
.sev-medium .badge, .badge.sev-medium { color: var(--medium); }
.sev-low .badge, .badge.sev-low { color: var(--low); }
.sev-info .badge, .badge.sev-info { color: var(--info); }
.finding {
  background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--muted);
  border-radius: 12px; padding: 1.1rem 1.25rem; margin-bottom: 1rem;
}
.finding.sev-critical { border-left-color: var(--critical); }
.finding.sev-high { border-left-color: var(--high); }
.finding.sev-medium { border-left-color: var(--medium); }
.finding.sev-low { border-left-color: var(--low); }
.finding-meta {
  display: flex; flex-wrap: wrap; gap: 0.35rem 1rem; margin: 0.35rem 0 0.9rem;
  color: var(--muted); font-size: 0.85rem;
}
.finding-meta code { color: var(--text); }
code {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.88em; background: var(--panel-alt); padding: 0.1rem 0.35rem; border-radius: 4px;
}
.field { margin-top: 0.85rem; }
.field-label {
  margin: 0 0 0.15rem; color: var(--muted); font-size: 0.75rem;
  letter-spacing: 0.07em; text-transform: uppercase;
}
pre {
  margin: 0.3rem 0 0; padding: 0.75rem; overflow-x: auto;
  background: var(--panel-alt); border: 1px solid var(--border); border-radius: 8px;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.86rem; white-space: pre-wrap; word-break: break-word;
}
ul.notes { margin: 0; padding-left: 1.2rem; }
ul.notes li { margin: 0.35rem 0; }
.note-warning { color: var(--medium); }
.note-critical { color: var(--critical); }
.note-muted { color: var(--muted); }
.empty {
  background: var(--panel); border: 1px dashed var(--border); border-radius: 12px;
  padding: 1.5rem; color: var(--muted);
}
footer {
  margin-top: 3rem; padding-top: 1.25rem; border-top: 1px solid var(--border);
  color: var(--muted); font-size: 0.85rem;
}
.toc {
  margin: 1.25rem 0 0; padding: 0; list-style: none;
  display: flex; flex-wrap: wrap; gap: 0.5rem;
}
.toc a {
  display: inline-block; padding: 0.25rem 0.6rem; border: 1px solid var(--border);
  border-radius: 999px; text-decoration: none; font-size: 0.85rem;
}
.toc a:hover { border-color: var(--accent); }
@media (max-width: 640px) {
  body { padding: 1.5rem 1rem 3rem; }
  table { font-size: 0.88rem; }
  th, td { padding: 0.45rem 0.4rem; }
  .bar { min-width: 48px; }
}
@media print {
  :root { color-scheme: light; }
  body { background: #fff; color: #111; }
  .card, .finding, .empty, pre, code { background: #fff; border-color: #ccc; }
  .toc, .skip-link { display: none; }
  a { color: #0b4faa; }
}
"""


def render_html(
    report: ScanReport,
    *,
    exit_code: int,
    min_severity: Severity = Severity.INFO,
    target_path: str | None = None,
) -> str:
    """Render ``report`` as one self-contained HTML document.

    Every finding is included, matching the JSON document: ``--max-findings`` is a terminal
    presentation limit and never truncates a saved report.
    """
    result = build_scan_result(report, exit_code=exit_code, min_severity=min_severity)
    title = f"RepoLens report — {report.repository_name}"
    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_esc(title)}</title>",
        f'<meta name="generator" content="{_esc(f"RepoLens {report.repolens_version}")}">',
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        '<a class="skip-link" href="#findings">Skip to findings</a>',
        '<div class="wrap">',
        _header(report, target_path),
        "<main>",
        _toc(),
        _status_section(result),
        _scan_section(report),
        _severity_section(report),
        _coverage_section(result),
        _analyzers_section(report),
        _findings_section(report),
        _warnings_section(report),
        "</main>",
        _footer(report, result),
        "</div>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts)


# --------------------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------------------


def _header(report: ScanReport, target_path: str | None) -> str:
    subtitle = "Static analysis report"
    if target_path:
        subtitle = f"Static analysis report for <code>{_esc(target_path)}</code>"
    return "\n".join(
        [
            '<header class="page-header">',
            f'<p class="eyebrow">RepoLens {_esc(report.repolens_version)} · '
            f"schema {_esc(report.schema_version)}</p>",
            f"<h1>{_esc(report.repository_name)}</h1>",
            f'<p class="subtitle">{subtitle}</p>',
            "</header>",
        ]
    )


def _toc() -> str:
    links = [
        ("result", "Result"),
        ("scan", "Scan"),
        ("severity", "Severity"),
        ("coverage", "Coverage"),
        ("analyzers", "Analyzers"),
        ("findings", "Findings"),
    ]
    items = "".join(f'<li><a href="#{anchor}">{_esc(label)}</a></li>' for anchor, label in links)
    return f'<nav aria-label="Report sections"><ul class="toc">{items}</ul></nav>'


def _status_section(result: ScanResult) -> str:
    label, detail = _STATUS_LABELS[result.status]
    coverage = "Complete" if result.is_complete else "Incomplete"
    return "\n".join(
        [
            '<section aria-labelledby="result-heading" id="result">',
            '<h2 id="result-heading">Result</h2>',
            f'<div class="card status-card status-{result.status.value}">',
            f'<p class="status-label">{_esc(label)}</p>',
            f'<p class="status-detail">{_esc(detail)}</p>',
            '<dl class="grid">',
            f"<div><dt>Exit code</dt><dd>{result.exit_code}</dd></div>",
            f"<div><dt>Coverage</dt><dd>{coverage}</dd></div>",
            f"<div><dt>Severity threshold</dt><dd>{_esc(result.min_severity.value)}</dd></div>",
            f"<div><dt>Findings at or above</dt>"
            f"<dd>{result.findings_at_or_above_threshold} of {result.findings_total}</dd></div>",
            "</dl>",
            "</div>",
            "</section>",
        ]
    )


def _scan_section(report: ScanReport) -> str:
    discovery = report.discovery
    languages = ", ".join(language.value for language in discovery.detected_languages) or "none"
    facts = [
        ("Files scanned", f"{discovery.total_files_scanned}"),
        ("Total size", format_bytes(discovery.total_bytes_scanned)),
        ("Scan duration", f"{report.duration_ms:.0f} ms"),
        ("Languages", languages),
        ("Scanned at", report.scanned_at.isoformat()),
        ("Sensitive files detected", f"{discovery.sensitive_files_detected}"),
        ("Excluded directories", f"{discovery.skipped_excluded_count}"),
    ]
    cells = "".join(
        f"<div><dt>{_esc(name)}</dt><dd>{_esc(value)}</dd></div>" for name, value in facts
    )
    return "\n".join(
        [
            '<section aria-labelledby="scan-heading" id="scan">',
            '<h2 id="scan-heading">Scan</h2>',
            '<div class="card">',
            f'<dl class="grid">{cells}</dl>',
            "</div>",
            "</section>",
        ]
    )


def _severity_section(report: ScanReport) -> str:
    counts = report.counts_by_severity()
    largest = max(counts.values(), default=0)
    rows: list[str] = []
    for severity in _SEVERITY_SUMMARY_ORDER:
        count = counts[severity]
        percent = (count / largest * 100) if largest else 0
        rows.append(
            f'<tr class="sev-{severity.value}">'
            f'<th scope="row"><span class="badge">{_esc(_SEVERITY_LABELS[severity])}</span></th>'
            f'<td class="num">{count}</td>'
            f'<td><div class="bar"><span style="width: {percent:.0f}%"></span></div></td>'
            "</tr>"
        )
    return "\n".join(
        [
            '<section aria-labelledby="severity-heading" id="severity">',
            '<h2 id="severity-heading">Findings by severity</h2>',
            "<table>",
            "<caption>Every finding in the report, including those below the severity "
            "threshold.</caption>",
            '<thead><tr><th scope="col">Severity</th><th scope="col" class="num">Count</th>'
            '<th scope="col">Share of the largest group</th></tr></thead>',
            f"<tbody>{''.join(rows)}</tbody>",
            "</table>",
            "</section>",
        ]
    )


def _coverage_section(result: ScanResult) -> str:
    if result.is_complete:
        body = '<p class="note-muted">Every check RepoLens set out to run completed.</p>'
    else:
        reasons = "".join(
            f"<li><code>{_esc(reason.value)}</code></li>" for reason in result.incomplete_reasons
        )
        body = (
            '<p class="note-critical">Part of the repository was not verified, so this report '
            "cannot be treated as a complete result.</p>"
            '<div class="field"><p class="field-label">Reasons</p>'
            f'<ul class="notes">{reasons}</ul></div>'
        )
    return "\n".join(
        [
            '<section aria-labelledby="coverage-heading" id="coverage">',
            '<h2 id="coverage-heading">Coverage</h2>',
            f'<div class="card">{body}</div>',
            "</section>",
        ]
    )


def _analyzers_section(report: ScanReport) -> str:
    if not report.analyzer_outcomes:
        return "\n".join(
            [
                '<section aria-labelledby="analyzers-heading" id="analyzers">',
                '<h2 id="analyzers-heading">Analyzer coverage</h2>',
                '<div class="card"><p class="note-muted">No analyzers were registered.</p></div>',
                "</section>",
            ]
        )
    rows: list[str] = []
    for outcome in report.analyzer_outcomes:
        rows.append(
            "<tr>"
            f'<th scope="row"><code>{_esc(outcome.analyzer_name)}</code></th>'
            f"<td>{_esc(outcome.status.value)}</td>"
            f'<td class="num">{outcome.findings_count}</td>'
            f'<td class="num">{outcome.duration_ms:.0f} ms</td>'
            f"<td>{_analyzer_detail(outcome)}</td>"
            "</tr>"
        )
    return "\n".join(
        [
            '<section aria-labelledby="analyzers-heading" id="analyzers">',
            '<h2 id="analyzers-heading">Analyzer coverage</h2>',
            "<table>",
            "<caption>Outcome of every registered analyzer, including optional tools that were "
            "not installed.</caption>",
            '<thead><tr><th scope="col">Analyzer</th><th scope="col">Status</th>'
            '<th scope="col" class="num">Findings</th><th scope="col" class="num">Duration</th>'
            '<th scope="col">Detail</th></tr></thead>',
            f"<tbody>{''.join(rows)}</tbody>",
            "</table>",
            "</section>",
        ]
    )


def _analyzer_detail(outcome: AnalyzerOutcome) -> str:
    parts: list[str] = []
    if outcome.message:
        parts.append(_esc(outcome.message))
    if outcome.coverage_truncated:
        parts.append(_esc("Covered only part of the repository (built-in limit reached)."))
    if outcome.coverage_incomplete and outcome.status is not AnalyzerStatus.UNAVAILABLE:
        parts.append(_esc("Started but did not complete, so its coverage is incomplete."))
    return "<br>".join(parts) or '<span class="note-muted">—</span>'


def _findings_section(report: ScanReport) -> str:
    if not report.findings:
        body = '<div class="empty">No findings were reported for this repository.</div>'
    else:
        body = "\n".join(_finding_card(finding) for finding in report.findings)
    return "\n".join(
        [
            '<section aria-labelledby="findings-heading" id="findings">',
            f'<h2 id="findings-heading">Findings ({len(report.findings)})</h2>',
            body,
            "</section>",
        ]
    )


def _finding_card(finding: Finding) -> str:
    location = _format_location(finding)
    meta = [
        f"<span>Rule <code>{_esc(finding.rule_id)}</code></span>",
        f"<span>Location <code>{_esc(location)}</code></span>",
        f"<span>Category {_esc(finding.category.value)}</span>",
        f"<span>Confidence {_esc(finding.confidence.value)}</span>",
    ]
    source = f"{finding.source.tool}"
    if finding.source.tool_version:
        source += f" {finding.source.tool_version}"
    meta.append(f"<span>Source {_esc(source)}</span>")

    fields = [("Explanation", finding.explanation), ("Recommendation", finding.recommendation)]
    blocks: list[str] = []
    if finding.evidence:
        blocks.append(
            '<div class="field"><p class="field-label">Evidence</p>'
            f"<pre>{_esc(finding.evidence)}</pre></div>"
        )
    for label, text in fields:
        blocks.append(
            f'<div class="field"><p class="field-label">{label}</p><p>{_esc(text)}</p></div>'
        )
    blocks.append(
        '<div class="field"><p class="field-label">Verification</p>'
        f"<p>{_esc(finding.verification)}</p></div>"
    )
    rule_link = _rule_link(finding)
    if rule_link:
        blocks.append(f'<div class="field">{rule_link}</div>')

    return "\n".join(
        [
            f'<article class="finding sev-{finding.severity.value}" '
            f'aria-labelledby="finding-{_esc(finding.fingerprint or finding.rule_id)}">',
            f'<h3 id="finding-{_esc(finding.fingerprint or finding.rule_id)}">'
            f'<span class="badge">{_esc(_SEVERITY_LABELS[finding.severity])}</span> '
            f"{_esc(finding.title)}</h3>",
            f'<p class="finding-meta">{"".join(meta)}</p>',
            *blocks,
            "</article>",
        ]
    )


def _safe_url(raw: str | None) -> str | None:
    """Return ``raw`` as an absolute ``http(s)`` URL, or ``None`` if it is anything else.

    Rule URLs are repository-supplied data, so they are *never* trusted: the scheme must be
    ``http``/``https`` (which rejects ``javascript:``, ``data:``, ``vbscript:``, ``file:``,
    protocol-relative ``//host`` URLs, and opaque ``http:host`` forms), a host must be
    present, embedded credentials and any whitespace or control character disqualify the URL
    outright. The returned value is stripped, so the attribute never carries leading or
    trailing whitespace.
    """
    if not raw:
        return None
    url = raw.strip()
    if not url or any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return None
    if parts.username is not None or parts.password is not None:
        # Never emit credentials into a report that may be shared or committed.
        return None
    return url


def _rule_link(finding: Finding) -> str | None:
    """Return a link only for safe absolute http(s) URLs (see :func:`_safe_url`)."""
    url = _safe_url(finding.source.rule_url)
    if url is None:
        return None
    return (
        f'<a href="{_esc(url)}" rel="noopener noreferrer">Rule documentation for '
        f"<code>{_esc(finding.rule_id)}</code></a>"
    )


def _warnings_section(report: ScanReport) -> str:
    """Disclose every reason a reader should not treat this report as a full picture."""
    discovery = report.discovery
    warnings: list[tuple[str, str]] = []
    if discovery.unreadable_directory_count or discovery.unreadable_entry_count:
        parts = []
        if discovery.unreadable_directory_count:
            parts.append(_count(discovery.unreadable_directory_count, "directory", "directories"))
        if discovery.unreadable_entry_count:
            parts.append(_count(discovery.unreadable_entry_count, "entry", "entries"))
        warnings.append(
            ("note-critical", f"Could not read {' and '.join(parts)}, so the scan is incomplete.")
        )
    if discovery.skipped_by_depth_count:
        warnings.append(
            (
                "note-critical",
                f"{_count(discovery.skipped_by_depth_count, 'directory', 'directories')} were "
                "nested deeper than the supported limit and were not scanned.",
            )
        )
    limits = []
    if discovery.truncated_by_file_limit:
        limits.append("maximum file count")
    if discovery.truncated_by_byte_limit:
        limits.append("maximum total bytes")
    if limits:
        warnings.append(
            (
                "note-critical",
                f"Discovery stopped early after reaching the {' and '.join(limits)} limit, so "
                "results may be incomplete.",
            )
        )
    if discovery.skipped_oversized_count:
        warnings.append(
            (
                "note-muted",
                f"{_count(discovery.skipped_oversized_count, 'file', 'files')} exceeded the "
                "per-file size limit and were not analyzed.",
            )
        )
    if discovery.skipped_symlink_count:
        warnings.append(
            (
                "note-muted",
                f"{_count(discovery.skipped_symlink_count, 'symbolic link', 'symbolic links')} "
                "were not followed.",
            )
        )
    if report.ai_advisories:
        total = len(report.ai_advisories)
        noun = _count(total, "AI advisory", "AI advisories")
        verb = "is" if total == 1 else "are"
        warnings.append(
            (
                "note-muted",
                f"{noun} {verb} present in the report data; they are non-authoritative and are "
                "not shown as findings.",
            )
        )
    if not warnings:
        return ""
    items = "".join(f'<li class="{css}">{_esc(text)}</li>' for css, text in warnings)
    return "\n".join(
        [
            '<section aria-labelledby="warnings-heading" id="warnings">',
            '<h2 id="warnings-heading">Notes</h2>',
            f'<div class="card"><ul class="notes">{items}</ul></div>',
            "</section>",
        ]
    )


def _footer(report: ScanReport, result: ScanResult) -> str:
    reasons = ", ".join(reason.value for reason in result.incomplete_reasons) or "none"
    return "\n".join(
        [
            "<footer>",
            f"<p>Generated by RepoLens {_esc(report.repolens_version)} · document schema "
            f"{_esc(report.schema_version)} · status <code>{_esc(result.status.value)}</code> · "
            f"incomplete reasons: {_esc(reasons)}</p>",
            "<p>This file is self-contained: it loads no scripts, fonts, or styles from the "
            "network.</p>",
            "</footer>",
        ]
    )


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _esc(value: object) -> str:
    """Escape untrusted text for HTML text and attribute contexts."""
    return html.escape(str(value), quote=True)


def _count(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _format_location(finding: Finding) -> str:
    location = finding.location
    if location is None:
        return "(repository-wide)"
    if location.start_line is None:
        return location.path
    return f"{location.path}:{location.start_line}"


__all__ = ["render_html"]
