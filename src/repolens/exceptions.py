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


class ScanDocumentError(RepoLensError, ValueError):
    """Raised when a serialized scan document cannot be read safely.

    Also a :class:`ValueError`, so callers that already guard ``json``/``model_validate``
    with ``except ValueError`` keep working unchanged.
    """


class UnsupportedSchemaVersionError(ScanDocumentError):
    """Raised when a document's schema version is missing, malformed, or unsupported.

    A parser only understands the major versions it declares in
    :data:`repolens.models.SUPPORTED_SCHEMA_MAJOR_VERSIONS`. Reading a document from a
    different major version would mean guessing at its meaning, so it is refused instead.
    """


class UnsupportedSchemaValueError(ScanDocumentError):
    """Raised when a document contains an enum value this parser does not understand.

    Forward-compatible parsing ignores *unknown members* (additive changes), but an unknown
    value for a known member could silently change what a scan verdict means — for example an
    unrecognized ``result.status`` or ``incomplete_reasons[]`` entry. Rather than coercing it
    to a neighbouring value, parsing stops.
    """
