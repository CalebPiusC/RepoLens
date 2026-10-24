"""Built-in and external analyzer integrations for RepoLens."""

from __future__ import annotations

from repolens.analyzers.base import Analyzer, AnalyzerAvailability, AnalyzerTimeoutError
from repolens.analyzers.structure import StructureAnalyzer


def default_analyzers() -> list[Analyzer]:
    """Return the default ordered analyzer suite registered for RepoLens."""
    return [StructureAnalyzer()]


__all__ = [
    "Analyzer",
    "AnalyzerAvailability",
    "AnalyzerTimeoutError",
    "StructureAnalyzer",
    "default_analyzers",
]
