"""Deterministic, machine-readable JSON serialization of a :class:`ScanReport`.

This module owns exactly one concern: turning the *existing* report models into a single JSON
document. It never re-declares findings, analyzers, or discovery data — the document body is
``ScanReport.model_dump(mode="json")``, so the JSON and the terminal reporter can never drift
apart. The only addition is a ``result`` member derived from the same
:func:`repolens.reporting.evaluate` verdict that decides the exit code.

Guarantees (documented in the README section "Machine-readable JSON output"):

* **One document on stdout.** No banners, progress text, ANSI color, or human-readable
  result lines are mixed in; diagnostics continue to go to stderr.
* **Stable member names and order.** Report members appear in ``ScanReport`` field order,
  followed by ``result``; ``result`` members appear in ``ScanResult`` field order.
* **Stable ordering of collections.** Findings and analyzer outcomes keep the order the
  engine produced (findings are already sorted by severity, category, path, line, rule ID,
  fingerprint); count maps always cover every enum member in declaration order.
* **ASCII-only output** (``ensure_ascii=True``), so the bytes are identical regardless of the
  console encoding — including Windows consoles that cannot represent non-ASCII names.
* **Everything except ``scanned_at`` and ``duration_ms`` is deterministic** for the same
  repository content and options.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, TypeVar, get_args, get_origin

from pydantic import BaseModel, ValidationError

from repolens.exceptions import (
    ScanDocumentError,
    UnsupportedSchemaValueError,
    UnsupportedSchemaVersionError,
)
from repolens.models import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_MAJOR_VERSIONS,
    AnalyzerStatus,
    IncompleteReason,
    ScanReport,
    ScanResult,
    ScanStatus,
    Severity,
)
from repolens.reporting import evaluate

_ModelT = TypeVar("_ModelT", bound=BaseModel)

JSON_INDENT: Final = 2
"""Indentation of the emitted document (two spaces, like the report examples in the README)."""

# Fixed emission order for ``incomplete_reasons``; membership, not analyzer order, decides.
_REASON_FOR_STATUS: Final[dict[AnalyzerStatus, IncompleteReason]] = {
    AnalyzerStatus.FAILED: IncompleteReason.ANALYZER_FAILED,
    AnalyzerStatus.TIMED_OUT: IncompleteReason.ANALYZER_TIMED_OUT,
}


def build_scan_result(
    report: ScanReport,
    *,
    exit_code: int,
    min_severity: Severity = Severity.INFO,
) -> ScanResult:
    """Derive the machine-readable verdict for ``report`` at ``min_severity``.

    ``exit_code`` is passed in rather than recomputed so the document can never disagree
    with the process exit status: both come from the caller's single
    :func:`repolens.cli.determine_exit_code` call.
    """
    verdict = evaluate(report, min_severity)

    reasons: set[IncompleteReason] = set()
    for outcome in verdict.incomplete_analyzers:
        reason = _REASON_FOR_STATUS.get(outcome.status)
        if reason is not None:
            reasons.add(reason)
    if verdict.partial_coverage_analyzers:
        reasons.add(IncompleteReason.ANALYZER_COVERAGE_TRUNCATED)
    if verdict.aborted_checks:
        reasons.add(IncompleteReason.CHECK_ABORTED)
    if verdict.discovery_failures:
        reasons.add(IncompleteReason.DISCOVERY_UNREADABLE)
    if verdict.discovery_truncated:
        reasons.add(IncompleteReason.DISCOVERY_TRUNCATED)
    if verdict.discovery_depth_limited:
        reasons.add(IncompleteReason.DISCOVERY_DEPTH_LIMITED)

    if verdict.has_findings and verdict.is_incomplete:
        status = ScanStatus.FINDINGS_AND_INCOMPLETE
    elif verdict.has_findings:
        status = ScanStatus.FINDINGS
    elif verdict.is_incomplete:
        status = ScanStatus.INCOMPLETE
    else:
        status = ScanStatus.CLEAN

    return ScanResult(
        exit_code=exit_code,
        min_severity=min_severity,
        status=status,
        has_findings=verdict.has_findings,
        is_complete=not verdict.is_incomplete,
        # Iterating the enum (not the set) keeps the list order independent of analyzer order.
        incomplete_reasons=[member for member in IncompleteReason if member in reasons],
        findings_total=verdict.total_findings,
        findings_at_or_above_threshold=len(verdict.findings_at_or_above),
        counts_by_severity=report.counts_by_severity(),
        counts_by_category=report.counts_by_category(),
    )


def build_json_document(
    report: ScanReport,
    *,
    exit_code: int,
    min_severity: Severity = Severity.INFO,
) -> dict[str, Any]:
    """Return the JSON document for ``report`` as a plain ``dict``.

    Every finding is included: the CLI's ``--max-findings`` limit is a presentation limit for
    the terminal table and deliberately does not apply here, so a machine consumer never sees
    a silently truncated finding list.
    """
    document: dict[str, Any] = report.model_dump(mode="json")
    document["result"] = build_scan_result(
        report, exit_code=exit_code, min_severity=min_severity
    ).model_dump(mode="json")
    return document


@dataclass(frozen=True, slots=True)
class ParsedScanDocument:
    """A CLI JSON document split back into its two validated models."""

    report: ScanReport
    result: ScanResult


_SCHEMA_VERSION_PATTERN: Final = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def _parse_schema_version(payload: Mapping[str, Any]) -> tuple[int, int, int]:
    """Return the ``(major, minor, patch)`` version of ``payload`` or refuse to continue."""
    raw = payload.get("schema_version")
    if not isinstance(raw, str):
        raise ScanDocumentError("scan document is missing a string 'schema_version' member")
    match = _SCHEMA_VERSION_PATTERN.match(raw)
    if match is None:
        raise UnsupportedSchemaVersionError(
            f"malformed scan schema version {raw!r}: expected MAJOR.MINOR.PATCH"
        )
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _require_supported_schema_version(payload: Mapping[str, Any]) -> tuple[int, int, int]:
    """Enforce the acceptance policy in :data:`repolens.models.SUPPORTED_SCHEMA_MAJOR_VERSIONS`."""
    version = _parse_schema_version(payload)
    supported = sorted(SUPPORTED_SCHEMA_MAJOR_VERSIONS)
    if version[0] not in SUPPORTED_SCHEMA_MAJOR_VERSIONS:
        raise UnsupportedSchemaVersionError(
            f"unsupported scan schema version {'.'.join(map(str, version))}: this RepoLens "
            f"({SCHEMA_VERSION}) reads major version(s) "
            f"{', '.join(str(major) for major in supported)}; upgrade RepoLens to read this "
            "document, or regenerate it with a matching version"
        )
    return version


def _candidate_models(annotation: object) -> list[type[BaseModel]]:
    """Return the ``BaseModel`` classes reachable directly from ``annotation``."""
    if get_origin(annotation) is None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            return [annotation]
        return []
    models: list[type[BaseModel]] = []
    for argument in get_args(annotation):
        models.extend(_candidate_models(argument))
    return models


def _project_value(annotation: object, value: Any) -> Any:
    """Drop unknown members from ``value`` according to ``annotation``, recursively."""
    candidates = _candidate_models(annotation)
    if len(candidates) != 1:  # unknown/ambiguous shape: leave it for Pydantic to judge
        return value
    model = candidates[0]
    if isinstance(value, Mapping):
        return _strip_unknown_members(model, value)
    if isinstance(value, list):
        return [
            _strip_unknown_members(model, item) if isinstance(item, Mapping) else item
            for item in value
        ]
    return value


def _strip_unknown_members(model: type[BaseModel], data: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only ``model``'s declared members, recursing into nested models."""
    projected: dict[str, Any] = {}
    for name, value in data.items():
        field = model.model_fields.get(name)
        if field is None:
            continue
        projected[name] = _project_value(field.annotation, value)
    return projected


def _enum_error(exc: ValidationError) -> tuple[str, object] | None:
    """Return the first ``(location, value)`` pair of an unknown enum value, if any."""
    for error in exc.errors():
        if error["type"] != "enum":
            continue
        location = ".".join(str(part) for part in error["loc"]) or "<document>"
        return location, error.get("input")
    return None


def _validate_forward_compatible(model: type[_ModelT], data: Mapping[str, Any]) -> _ModelT:
    """Validate ``data`` ignoring unknown members, but never guessing unknown values."""
    try:
        return model.model_validate(_strip_unknown_members(model, data))
    except ValidationError as exc:
        unknown = _enum_error(exc)
        if unknown is not None:
            location, value = unknown
            raise UnsupportedSchemaValueError(
                f"unsupported value {value!r} for '{location}': this RepoLens "
                f"({SCHEMA_VERSION}) does not understand it. Treat the scan as "
                "indeterminate rather than assuming a clean or complete result"
            ) from exc
        raise


def parse_json_document(
    document: str,
    *,
    strict: bool = True,
) -> ParsedScanDocument:
    """Parse a document produced by :func:`render_json` back into models.

    The ``schema_version`` is checked first, following the acceptance policy in
    :data:`repolens.models.SUPPORTED_SCHEMA_MAJOR_VERSIONS`: any minor/patch of a supported
    major version is accepted, and any other major version raises
    :class:`~repolens.exceptions.UnsupportedSchemaVersionError` instead of being decoded
    under the wrong assumptions.

    ``strict`` selects how additive changes are treated:

    * ``strict=True`` (default) — exact validation through the Pydantic models. Unknown
      members and unknown enum values both raise (``ValidationError``), which is the safest
      choice when a consumer wants to know that it saw the whole document.
    * ``strict=False`` — forward-compatible mode: unknown **members** anywhere in the object
      graph (document root, ``result``, ``findings[]``, ``analyzer_outcomes[]``,
      ``discovery``, …) are ignored, so a MINOR release's added field does not break the
      reader. Unknown **values** for a known member still stop parsing with
      :class:`~repolens.exceptions.UnsupportedSchemaValueError`, because coercing, say, an
      unrecognized ``result.status`` or ``incomplete_reasons[]`` entry could silently turn an
      incomplete scan into a clean one.

    The ``result`` member is validated separately because ``ScanReport`` forbids unknown
    members (``extra="forbid"``). Structural problems — not a JSON object, missing
    ``result`` — raise :class:`~repolens.exceptions.ScanDocumentError`; other malformed
    values raise ``ValidationError``.
    """
    payload: object = json.loads(document)
    if not isinstance(payload, dict):
        raise ScanDocumentError("scan document must be a JSON object")

    _require_supported_schema_version(payload)

    body: dict[str, Any] = {key: value for key, value in payload.items() if key != "result"}
    result_payload = payload.get("result")
    if result_payload is None:
        raise ScanDocumentError("scan document is missing the 'result' member")
    if not isinstance(result_payload, Mapping):
        raise ScanDocumentError("scan document 'result' member must be a JSON object")

    if strict:
        return ParsedScanDocument(
            report=ScanReport.model_validate(body),
            result=ScanResult.model_validate(result_payload),
        )

    return ParsedScanDocument(
        report=_validate_forward_compatible(ScanReport, body),
        result=_validate_forward_compatible(ScanResult, result_payload),
    )


def render_json(
    report: ScanReport,
    *,
    exit_code: int,
    min_severity: Severity = Severity.INFO,
) -> str:
    """Render ``report`` as one printable JSON document (without a trailing newline)."""
    return json.dumps(
        build_json_document(report, exit_code=exit_code, min_severity=min_severity),
        indent=JSON_INDENT,
        ensure_ascii=True,
        allow_nan=False,
    )


__all__ = [
    "JSON_INDENT",
    "ParsedScanDocument",
    "build_json_document",
    "build_scan_result",
    "parse_json_document",
    "render_json",
]
