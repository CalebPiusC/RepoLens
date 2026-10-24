"""Base abstractions for RepoLens static analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from repolens.config import ScanConfig
from repolens.discovery import RepositoryContext
from repolens.models import Finding


@dataclass(frozen=True, slots=True)
class AnalyzerAvailability:
    """Result of checking whether an analyzer's runtime dependencies are available."""

    available: bool
    version: str | None = None
    reason: str | None = None


class AnalyzerTimeoutError(RuntimeError):
    """Raised by an analyzer when its underlying tool exceeds its time budget."""


class Analyzer(ABC):
    """Minimal contract implemented by all built-in and external tool analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable machine-friendly identifier for this analyzer."""

    def is_applicable(self, context: RepositoryContext) -> bool:
        """Return True if this analyzer applies to the discovered repository."""
        return True

    def check_availability(self) -> AnalyzerAvailability:
        """Check if external binaries or optional packages required by this analyzer exist."""
        return AnalyzerAvailability(available=True)

    @abstractmethod
    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        """Run static analysis against ``context`` and return normalized findings."""
