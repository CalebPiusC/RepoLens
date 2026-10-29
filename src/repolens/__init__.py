"""RepoLens — open-source repository health checker for Python and JS/TS projects."""

from __future__ import annotations

__version__ = "0.1.0"

from repolens.config import ScanConfig
from repolens.engine import ScanEngine
from repolens.exceptions import (
    ScanDocumentError,
    UnsupportedSchemaValueError,
    UnsupportedSchemaVersionError,
)
from repolens.models import (
    SCHEMA_MAJOR_VERSION,
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_MAJOR_VERSIONS,
    AIAdvisory,
    AnalyzerOutcome,
    AnalyzerStatus,
    Category,
    Confidence,
    DetectedLanguage,
    DiscoverySummary,
    Finding,
    FindingLocation,
    FindingSource,
    IncompleteReason,
    ScanReport,
    ScanResult,
    ScanStatus,
    Severity,
    SourceKind,
)

__all__ = [
    "SCHEMA_MAJOR_VERSION",
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_MAJOR_VERSIONS",
    "AIAdvisory",
    "AnalyzerOutcome",
    "AnalyzerStatus",
    "Category",
    "Confidence",
    "DetectedLanguage",
    "DiscoverySummary",
    "Finding",
    "FindingLocation",
    "FindingSource",
    "IncompleteReason",
    "ScanConfig",
    "ScanDocumentError",
    "ScanEngine",
    "ScanReport",
    "ScanResult",
    "ScanStatus",
    "Severity",
    "SourceKind",
    "UnsupportedSchemaValueError",
    "UnsupportedSchemaVersionError",
    "__version__",
]
