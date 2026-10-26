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


class AnalyzerUnavailableError(RuntimeError):
    """Raised when a required external tool or service disappears mid-scan."""


class AnalyzerExecutionError(RuntimeError):
    """Raised when an external tool fails, crashes, or emits unusable output."""


class Analyzer(ABC):
    """Minimal contract implemented by all built-in and external tool analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable machine-friendly identifier for this analyzer."""

    def is_applicable(self, context: RepositoryContext) -> bool:
        """Return True if this analyzer applies to the discovered repository."""
        return True

    def skip_reason(self, context: RepositoryContext, config: ScanConfig) -> str | None:
        """Return a human-readable reason to skip this analyzer, or None to run it.

        Used to distinguish a deliberate skip (for example optional network checks that
        the caller did not opt into) from a missing runtime dependency.
        """
        return None

    def check_availability(self) -> AnalyzerAvailability:
        """Check if external binaries or optional packages required by this analyzer exist."""
        return AnalyzerAvailability(available=True)

    def completion_message(self) -> str | None:
        """Return optional telemetry to record when the analyzer completes successfully."""
        return None

    def coverage_partial(self) -> bool:
        """Return True when the last run covered only part of the eligible repository files.

        Resource limits (for example the per-tool file cap) can be hit while still
        producing a "completed" outcome; reporting that honestly keeps a partially
        analyzed repository from looking clean.
        """
        return False

    @abstractmethod
    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        """Run static analysis against ``context`` and return normalized findings."""
