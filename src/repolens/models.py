"""Core Pydantic v2 data models for RepoLens findings, advisories, and scan reports."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from repolens.redaction import redact_secrets

SCHEMA_VERSION: Final = "1.1.0"
"""Version of the serialized scan document (see "Machine-readable JSON output" in the README).

The version identifies the **shape** of a serialized :class:`ScanReport` (and therefore of
the JSON document the CLI emits), independently of ``repolens_version``, which identifies the
package release. It follows semantic versioning:

* **MAJOR** — a field, enum value, or field *meaning* is removed or changed, or a previously
  optional member becomes required. Consumers must be updated.
* **MINOR** — purely additive: a new field, a new optional member, or a new enum value.
  Consumers must ignore members they do not know.
* **PATCH** — documentation or clarification only; the emitted shape is unchanged.

``1.1.0`` is the first version documented as a stability contract. It adds the CLI
``result`` member to the ``1.0.0`` report fields; nothing from ``1.0.0`` was renamed,
removed, or re-typed.
"""

SCHEMA_MAJOR_VERSION: Final = int(SCHEMA_VERSION.split(".", 1)[0])
"""Major component of :data:`SCHEMA_VERSION` (``1`` for ``1.1.0``)."""

SUPPORTED_SCHEMA_MAJOR_VERSIONS: Final[frozenset[int]] = frozenset({SCHEMA_MAJOR_VERSION})
"""Schema major versions :func:`repolens.json_output.parse_json_document` accepts.

Acceptance policy for a parser shipped with ``SCHEMA_VERSION``:

* **Same major, any minor/patch** (newer *or* older) — accepted. Additive MINOR changes are
  tolerated as documented in the README: unknown members are ignored, but an unknown value
  for a known member stops parsing rather than being guessed.
* **Different major** (including older ``0.x`` documents) — rejected with
  :class:`repolens.exceptions.UnsupportedSchemaVersionError`. A major bump means a member was
  removed, renamed, or re-typed, so the old meaning of a field cannot be assumed.
"""


class Category(StrEnum):
    """Supported repository analysis categories."""

    CODE_QUALITY = "code_quality"
    SECURITY = "security"
    DEPENDENCIES = "dependencies"
    DOCUMENTATION = "documentation"
    TESTING = "testing"
    STRUCTURE = "structure"


class Severity(StrEnum):
    """Normalized severity levels ordered from highest to lowest impact."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank used for deterministic sorting and threshold checks."""
        return _SEVERITY_RANKS[self]


_SEVERITY_RANKS: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class Confidence(StrEnum):
    """Confidence level for a deterministic finding."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SourceKind(StrEnum):
    """Origin classification separating deterministic scanners from AI suggestions."""

    DETERMINISTIC = "deterministic"
    AI_ADVISORY = "ai_advisory"


class AnalyzerStatus(StrEnum):
    """Execution outcome of an individual analyzer run."""

    COMPLETED = "completed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class ScanStatus(StrEnum):
    """Overall verdict of a completed scan, as reported by the CLI ``result`` member.

    Mirrors the terminal "Result:" line and the exit-code policy: ``FINDINGS`` and
    ``FINDINGS_AND_INCOMPLETE`` are the two states that exit ``1``, ``INCOMPLETE`` exits
    ``3``, and only ``CLEAN`` exits ``0``.
    """

    CLEAN = "clean"
    FINDINGS = "findings"
    INCOMPLETE = "incomplete"
    FINDINGS_AND_INCOMPLETE = "findings_and_incomplete"


class IncompleteReason(StrEnum):
    """Machine-readable reasons why a scan did not cover the whole repository.

    An empty list means the scan verified everything it set out to check. An analyzer that
    never started because an optional tool is missing is *not* a reason here: it is reported
    through ``analyzer_outcomes[].status == "unavailable"`` and does not change the exit code.
    """

    ANALYZER_FAILED = "analyzer_failed"
    ANALYZER_TIMED_OUT = "analyzer_timed_out"
    ANALYZER_COVERAGE_TRUNCATED = "analyzer_coverage_truncated"
    CHECK_ABORTED = "check_aborted"
    DISCOVERY_UNREADABLE = "discovery_unreadable"
    DISCOVERY_TRUNCATED = "discovery_truncated"
    DISCOVERY_DEPTH_LIMITED = "discovery_depth_limited"


class DetectedLanguage(StrEnum):
    """Primary programming languages supported by RepoLens."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"


class FindingLocation(BaseModel):
    """Repository-relative file and line span affected by a finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=2048)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)

    @field_validator("path")
    @classmethod
    def _validate_relative_posix_path(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or "\x00" in cleaned:
            raise ValueError("Location path must be a non-empty string without NUL bytes")
        if "\\" in cleaned:
            raise ValueError("Location path must use forward slashes (POSIX format)")
        if cleaned.startswith("/") or (len(cleaned) >= 2 and cleaned[1] == ":"):
            raise ValueError("Location path must be repository-relative, not absolute")

        posix = PurePosixPath(cleaned)
        if any(part in ("..", "") for part in posix.parts):
            raise ValueError("Location path must not contain '..' or empty path segments")
        normalized = posix.as_posix()
        if normalized == ".":
            raise ValueError("Location path must reference a specific file or directory")
        return normalized

    @model_validator(mode="after")
    def _validate_line_span(self) -> Self:
        if self.end_line is not None and self.start_line is None:
            raise ValueError("end_line cannot be set when start_line is None")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class FindingSource(BaseModel):
    """Provenance record identifying the scanner or model that produced an item."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: SourceKind
    tool: str = Field(min_length=1, max_length=128)
    tool_version: str | None = Field(default=None, max_length=64)
    rule_url: str | None = Field(default=None, max_length=512)


class Finding(BaseModel):
    """Normalized deterministic finding produced by a built-in or external analyzer.

    AI-generated hypotheses are strictly prohibited from being represented as ``Finding``
    instances; they must use ``AIAdvisory`` instead.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(min_length=2, max_length=128)
    category: Category
    severity: Severity
    confidence: Confidence = Confidence.HIGH
    title: str = Field(min_length=3, max_length=240)
    location: FindingLocation | None = None
    evidence: str | None = None
    explanation: str = Field(min_length=5, max_length=4000)
    recommendation: str = Field(min_length=5, max_length=4000)
    verification: str = Field(min_length=5, max_length=2000)
    source: FindingSource
    fingerprint: str = Field(default="", max_length=64)

    @field_validator("evidence")
    @classmethod
    def _scrub_evidence(cls, value: str | None) -> str | None:
        if value is None:
            return None
        scrubbed = redact_secrets(value, max_length=500).strip()
        return scrubbed or None

    @model_validator(mode="after")
    def _enforce_deterministic_and_fingerprint(self) -> Self:
        if self.source.kind != SourceKind.DETERMINISTIC:
            raise ValueError(
                "Finding.source.kind must be 'deterministic'; AI suggestions must use AIAdvisory"
            )
        if not self.fingerprint:
            if self.location:
                start = self.location.start_line or 0
                end = self.location.end_line or 0
                loc_key = f"{self.location.path}:{start}:{end}"
            else:
                loc_key = "<repo>"
            payload = "|".join(
                (
                    self.source.tool,
                    self.rule_id,
                    self.category.value,
                    loc_key,
                    self.title,
                )
            )
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
            object.__setattr__(self, "fingerprint", digest)
        return self


class AIAdvisory(BaseModel):
    """Non-authoritative AI-generated explanation or improvement suggestion.

    Stored separately from deterministic findings so AI output is never presented
    as a confirmed vulnerability or counted toward failure thresholds.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    advisory_id: str = Field(min_length=2, max_length=128)
    related_finding_fingerprints: list[str] = Field(default_factory=list)
    summary: str = Field(min_length=5, max_length=4000)
    suggested_improvement: str = Field(min_length=5, max_length=4000)
    verification: str = Field(min_length=5, max_length=2000)
    disclaimer: str = Field(
        default=(
            "AI-generated advisory based on scanner metadata; verify manually before applying."
        ),
        min_length=10,
        max_length=500,
    )
    source: FindingSource

    @model_validator(mode="after")
    def _enforce_ai_source(self) -> Self:
        if self.source.kind != SourceKind.AI_ADVISORY:
            raise ValueError("AIAdvisory.source.kind must be 'ai_advisory'")
        return self


class AnalyzerOutcome(BaseModel):
    """Execution telemetry and status for a single analyzer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    analyzer_name: str = Field(min_length=1, max_length=128)
    status: AnalyzerStatus
    findings_count: int = Field(default=0, ge=0)
    duration_ms: float = Field(default=0.0, ge=0.0)
    message: str | None = Field(default=None, max_length=1000)
    # True when the analyzer ran successfully but only covered part of the eligible files
    # (for example because a per-tool file cap was reached).
    coverage_truncated: bool = False
    # True when the check was started but could not run to completion (for example a
    # requested network lookup failed mid-flight). Unlike a tool that was never installed,
    # nothing this check would have covered was verified, so coverage is incomplete.
    coverage_incomplete: bool = False

    @field_validator("message")
    @classmethod
    def _scrub_message(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return redact_secrets(value, max_length=500)


class DiscoverySummary(BaseModel):
    """Summary of safe repository discovery and applied resource limits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_files_scanned: int = Field(ge=0)
    total_bytes_scanned: int = Field(ge=0)
    skipped_excluded_count: int = Field(ge=0)
    skipped_symlink_count: int = Field(ge=0)
    skipped_oversized_count: int = Field(ge=0)
    sensitive_files_detected: int = Field(ge=0)
    truncated_by_file_limit: bool = False
    truncated_by_byte_limit: bool = False
    # Directories/entries the walker could not inspect (e.g. permission denied). These
    # mean the scan silently saw less of the repository than exists, so no consumer may
    # report such a scan as clean.
    unreadable_directory_count: int = Field(default=0, ge=0)
    unreadable_entry_count: int = Field(default=0, ge=0)
    # Directories skipped because they were nested deeper than the supported walk depth.
    skipped_by_depth_count: int = Field(default=0, ge=0)
    detected_languages: list[DetectedLanguage] = Field(default_factory=list)

    @property
    def has_discovery_failures(self) -> bool:
        """True when part of the tree could not be inspected at all."""
        return self.unreadable_directory_count > 0 or self.unreadable_entry_count > 0

    @property
    def depth_limited(self) -> bool:
        """True when a subtree was skipped for exceeding the supported nesting depth."""
        return self.skipped_by_depth_count > 0

    @property
    def is_partial(self) -> bool:
        """True when discovery stopped early or could not inspect part of the repository."""
        return (
            self.has_discovery_failures
            or self.truncated_by_file_limit
            or self.truncated_by_byte_limit
            or self.depth_limited
        )


class ScanReport(BaseModel):
    """Complete, serializable output of a RepoLens repository scan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # ``validate_default=True`` keeps the version contract honest: Pydantic does not validate
    # field defaults by default, so without it a malformed ``SCHEMA_VERSION`` constant would be
    # emitted verbatim instead of failing when the report is built.
    schema_version: str = Field(
        default=SCHEMA_VERSION, pattern=r"^\d+\.\d+\.\d+$", validate_default=True
    )
    repolens_version: str = Field(min_length=1, max_length=32)
    repository_name: str = Field(min_length=1, max_length=256)
    scanned_at: datetime
    duration_ms: float = Field(ge=0.0)
    discovery: DiscoverySummary
    analyzer_outcomes: list[AnalyzerOutcome] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    ai_advisories: list[AIAdvisory] = Field(default_factory=list)

    def counts_by_severity(self) -> dict[Severity, int]:
        """Return deterministic finding counts keyed by every severity level."""
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def counts_by_category(self) -> dict[Category, int]:
        """Return deterministic finding counts keyed by every analysis category."""
        counts = dict.fromkeys(Category, 0)
        for finding in self.findings:
            counts[finding.category] += 1
        return counts

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        """Return True if any deterministic finding meets or exceeds ``threshold``."""
        return any(f.severity.rank >= threshold.rank for f in self.findings)


class ScanResult(BaseModel):
    """Derived, machine-readable verdict for a scan, emitted as the CLI ``result`` member.

    This is not a second report: every value is computed from a :class:`ScanReport` by the
    same :func:`repolens.reporting.evaluate` logic that drives the terminal "Result:" line
    and :func:`repolens.cli.determine_exit_code`. It exists so a JSON consumer never has to
    re-implement the exit-code policy.

    ``counts_by_severity`` and ``counts_by_category`` always contain **every** enum member,
    including zero counts, in enum declaration order (severity: critical, high, medium, low,
    info; category: code_quality, security, dependencies, documentation, testing, structure).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    exit_code: int = Field(ge=0, le=130)
    min_severity: Severity
    status: ScanStatus
    has_findings: bool
    is_complete: bool
    incomplete_reasons: list[IncompleteReason] = Field(default_factory=list)
    findings_total: int = Field(ge=0)
    findings_at_or_above_threshold: int = Field(ge=0)
    counts_by_severity: dict[Severity, int]
    counts_by_category: dict[Category, int]

    @model_validator(mode="after")
    def _require_complete_count_maps(self) -> Self:
        # Zero counts must still be present, so consumers can read a key unconditionally.
        if set(self.counts_by_severity) != set(Severity):
            raise ValueError("counts_by_severity must contain one entry per severity")
        if set(self.counts_by_category) != set(Category):
            raise ValueError("counts_by_category must contain one entry per category")
        if any(count < 0 for count in self.counts_by_severity.values()) or any(
            count < 0 for count in self.counts_by_category.values()
        ):
            raise ValueError("finding counts must not be negative")
        return self
