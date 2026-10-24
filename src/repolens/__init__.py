"""RepoLens — open-source repository health checker for Python and JS/TS projects."""

from __future__ import annotations

__version__ = "0.1.0"

from repolens.config import ScanConfig
from repolens.engine import ScanEngine
from repolens.models import (
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
    ScanReport,
    Severity,
    SourceKind,
)

__all__ = [
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
    "ScanConfig",
    "ScanEngine",
    "ScanReport",
    "Severity",
    "SourceKind",
    "__version__",
]
