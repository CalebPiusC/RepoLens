"""Built-in and external analyzer integrations for RepoLens."""

from __future__ import annotations

from repolens.analyzers.advisories import OsvVulnerabilityAnalyzer
from repolens.analyzers.base import (
    Analyzer,
    AnalyzerAvailability,
    AnalyzerExecutionError,
    AnalyzerTimeoutError,
    AnalyzerUnavailableError,
)
from repolens.analyzers.dependencies import DependencyAnalyzer
from repolens.analyzers.documentation import DocumentationAnalyzer
from repolens.analyzers.jsts_lint import BiomeAnalyzer
from repolens.analyzers.python_lint import BanditAnalyzer, RuffAnalyzer
from repolens.analyzers.structure import StructureAnalyzer
from repolens.analyzers.testing import TestingAnalyzer


def default_analyzers() -> list[Analyzer]:
    """Return the default ordered analyzer suite registered for RepoLens.

    Deterministic, offline analyzers run first so a report always contains local results
    even when a later external tool or network check is unavailable.
    """
    return [
        StructureAnalyzer(),
        DependencyAnalyzer(),
        DocumentationAnalyzer(),
        TestingAnalyzer(),
        RuffAnalyzer(),
        BanditAnalyzer(),
        BiomeAnalyzer(),
        OsvVulnerabilityAnalyzer(),
    ]


__all__ = [
    "Analyzer",
    "AnalyzerAvailability",
    "AnalyzerExecutionError",
    "AnalyzerTimeoutError",
    "AnalyzerUnavailableError",
    "BanditAnalyzer",
    "BiomeAnalyzer",
    "DependencyAnalyzer",
    "DocumentationAnalyzer",
    "OsvVulnerabilityAnalyzer",
    "RuffAnalyzer",
    "StructureAnalyzer",
    "TestingAnalyzer",
    "default_analyzers",
]
