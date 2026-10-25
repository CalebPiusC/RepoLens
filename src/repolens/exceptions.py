"""Domain exceptions for RepoLens."""

from __future__ import annotations


class RepoLensError(Exception):
    """Base exception for all RepoLens operational errors."""


class DiscoveryError(RepoLensError):
    """Raised when a target repository path is invalid or violates safety checks."""


class PathSecurityError(DiscoveryError):
    """Raised when a path attempts symlink escape or directory traversal."""


class DiscoveryAbortedError(PathSecurityError):
    """Raised when discovery must abort after part of the repository was already scanned.

    Unlike the root-validation failures raised before the walk starts, this means a scan
    began and then stopped early, so it is an operational failure rather than a usage
    error: reporting "nothing was scanned" would be misleading.
    """


class SensitiveFileAccessError(RepoLensError):
    """Raised when an analyzer attempts to read contents of a sensitive file."""


class OversizedFileAccessError(RepoLensError):
    """Raised when an analyzer attempts to read a file exceeding size limits."""


class SubprocessExecutionError(RepoLensError):
    """Raised when a subprocess invocation violates safety constraints."""
