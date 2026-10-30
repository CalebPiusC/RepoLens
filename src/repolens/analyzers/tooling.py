"""Availability probing and bounded execution helpers for external static analyzers.

Every external tool invocation in RepoLens goes through this module so that:

* executables are resolved from a sanitized ``PATH`` (never a shell),
* arguments are passed as a structured list,
* a disposable working directory is used instead of the scanned repository,
* time and output budgets are enforced, and
* the repository's own tool configuration is never trusted by default.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import TypeVar

from repolens.analyzers.base import (
    AnalyzerAvailability,
    AnalyzerExecutionError,
    AnalyzerTimeoutError,
    AnalyzerUnavailableError,
)
from repolens.discovery import RepositoryContext
from repolens.exceptions import SubprocessExecutionError
from repolens.subprocess_runner import SubprocessResult, build_sanitized_env, run_safe_command

_VERSION_PROBE_TIMEOUT_SECONDS = 5.0
_VERSION_PROBE_MAX_OUTPUT_BYTES = 65_536
_VERSION_PATTERN = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")
_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class ToolAvailability:
    """Outcome of probing for an external tool executable."""

    available: bool
    executable: str | None = None
    version: str | None = None
    reason: str | None = None


def _extract_version(output: str) -> str | None:
    match = _VERSION_PATTERN.search(output)
    return match.group(1) if match is not None else None


def probe_tool(name: str, *, version_args: Sequence[str] = ("--version",)) -> ToolAvailability:
    """Probe ``name`` on the sanitized ``PATH`` and capture its version string.

    Probing only runs the tool's own ``--version`` flag; repository code is never executed.
    """
    if not name or "/" in name or "\\" in name:
        return ToolAvailability(available=False, reason="Invalid tool name.")

    path_env = build_sanitized_env().get("PATH")
    executable = shutil.which(name, path=path_env)
    if executable is None:
        return ToolAvailability(
            available=False,
            reason=f"`{name}` executable was not found on PATH (optional tool not installed).",
        )
    # `shutil.which` returns a relative path when the matching `PATH` entry is relative (for
    # example `PATH=.venv/bin:$PATH`). The tool is later executed from a different working
    # directory, so the path is anchored to the current directory here, while it is still valid.
    executable = str(Path(executable).resolve())

    version: str | None = None
    try:
        with tool_workspace() as workspace:
            result = run_safe_command(
                [executable, *version_args],
                cwd=workspace,
                timeout_seconds=_VERSION_PROBE_TIMEOUT_SECONDS,
                max_output_bytes=_VERSION_PROBE_MAX_OUTPUT_BYTES,
            )
    except (SubprocessExecutionError, OSError):
        # The binary exists but could not be probed; treat it as available without a version.
        return ToolAvailability(available=True, executable=executable, version=None)

    if not result.timed_out:
        version = _extract_version(result.stdout) or _extract_version(result.stderr)

    return ToolAvailability(available=True, executable=executable, version=version)


@lru_cache(maxsize=16)
def _cached_probe(name: str) -> ToolAvailability:
    return probe_tool(name)


def resolve_tool(name: str) -> ToolAvailability:
    """Return (and cache) availability information for external tool ``name``."""
    return _cached_probe(name)


def clear_tool_cache() -> None:
    """Drop cached tool availability information (used by tests and long-lived servers)."""
    _cached_probe.cache_clear()


@contextmanager
def tool_workspace() -> Iterator[Path]:
    """Yield a disposable, symlink-resolved working directory for an external tool.

    Cleanup tolerates a still-terminating tool process: Windows reports the directory as
    in use while the terminated child is shutting down, and a leaked scratch directory must
    never mask the analyzer outcome that is being reported.
    """
    with tempfile.TemporaryDirectory(prefix="repolens-tool-", ignore_cleanup_errors=True) as raw:
        yield Path(raw).resolve()


def iter_batches(items: Sequence[str], size: int) -> Iterator[Sequence[str]]:
    """Yield ``items`` in deterministic batches of at most ``size`` entries."""
    effective = max(size, 1)
    for start in range(0, len(items), effective):
        yield items[start : start + effective]


def select_source_files(
    context: RepositoryContext,
    suffixes: frozenset[str],
    limit: int,
) -> list[str]:
    """Return deterministic, safely discovered, non-ignored source files for tool input."""
    files, _ = select_source_files_with_status(context, suffixes, limit)
    return files


def select_source_files_with_status(
    context: RepositoryContext,
    suffixes: frozenset[str],
    limit: int,
) -> tuple[list[str], bool]:
    """Like :func:`select_source_files`, but also report whether ``limit`` was hit.

    The second element is ``True`` when more eligible files exist than the analyzer is
    allowed to hand to an external tool, which means the tool's verdict covers only part
    of the repository. Callers must surface that instead of silently reporting a pass.
    """
    selected: list[str] = []
    for item in context.files:
        if item.is_sensitive or item.is_oversized:
            continue
        if PurePosixPath(item.path).suffix.lower() not in suffixes:
            continue
        if context.has_gitignore and context.gitignore.is_ignored(item.path, is_dir=False):
            continue
        selected.append(item.path)
        if len(selected) >= limit:
            return selected, _has_more_eligible(context, suffixes, limit)
    return selected, False


def _has_more_eligible(context: RepositoryContext, suffixes: frozenset[str], limit: int) -> bool:
    """Return True when at least one further eligible file exists beyond ``limit``."""
    eligible = 0
    for item in context.files:
        if item.is_sensitive or item.is_oversized:
            continue
        if PurePosixPath(item.path).suffix.lower() not in suffixes:
            continue
        if context.has_gitignore and context.gitignore.is_ignored(item.path, is_dir=False):
            continue
        eligible += 1
        if eligible > limit:
            return True
    return False


def select_config_files(
    context: RepositoryContext, names: frozenset[str], limit: int = 10
) -> list[str]:
    """Return discovered repository files whose base name is in ``names``."""
    selected: list[str] = []
    for item in context.files:
        if item.is_sensitive or item.is_oversized:
            continue
        if PurePosixPath(item.path).name not in names:
            continue
        if context.has_gitignore and context.gitignore.is_ignored(item.path, is_dir=False):
            continue
        selected.append(item.path)
        if len(selected) >= limit:
            break
    return selected


def absolute_paths(root: Path, relative_paths: Sequence[str]) -> list[str]:
    """Join repository-relative POSIX paths onto ``root`` without trusting user input."""
    paths: list[str] = []
    for rel in relative_paths:
        parts = PurePosixPath(rel).parts
        if not parts or any(part in ("..", "", "/") for part in parts):
            continue
        paths.append(str(root.joinpath(*parts)))
    return paths


def repository_relative_path(raw_path: str, *, root: Path, cwd: Path) -> str | None:
    """Map a tool-reported path back to a repository-relative POSIX path, or None."""
    if not raw_path or "\x00" in raw_path:
        return None
    candidate = Path(raw_path)
    try:
        resolved = (candidate if candidate.is_absolute() else cwd / candidate).resolve()
    except OSError:
        return None
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return None
    if not relative.parts:
        return None
    return PurePosixPath(*relative.parts).as_posix()


def run_tool(
    name: str,
    args: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    max_output_bytes: int,
) -> SubprocessResult:
    """Run an already-probed external tool with structured arguments and hard budgets."""
    availability = resolve_tool(name)
    if not availability.available or availability.executable is None:
        raise AnalyzerUnavailableError(
            availability.reason or f"`{name}` is not available for static analysis."
        )

    argv = [availability.executable, *args]
    try:
        result = run_safe_command(
            argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
    except SubprocessExecutionError as exc:
        raise AnalyzerUnavailableError(f"`{name}` could not be executed safely: {exc}") from exc

    if result.timed_out:
        raise AnalyzerTimeoutError(
            f"`{name}` exceeded the {timeout_seconds:g}s analysis timeout and was terminated."
        )

    return result


def parse_diagnostic_stdout(
    tool_name: str,
    result: SubprocessResult,
    parser: Callable[[str], _T],
    *,
    fallback: _T,
) -> tuple[_T, str | None]:
    """Parse retained diagnostics and flag truncated stdout, independently of stderr.

    A truncated prefix can still contain a complete JSON document. If it cannot be
    parsed, keep prior batches rather than discarding already confirmed findings.
    Malformed output without truncation remains an execution error.
    """
    # Older callers may construct a result with only the aggregate flag. Without a
    # stream-specific stderr flag, conservatively treat that unknown loss as stdout loss.
    stdout_truncated = result.stdout_truncated or (
        result.output_truncated and not result.stderr_truncated
    )
    try:
        parsed = parser(result.stdout)
    except AnalyzerExecutionError:
        if not stdout_truncated:
            raise
        parsed = fallback
    reason = (
        f"{tool_name} diagnostic stdout was truncated; some diagnostics may be missing."
        if stdout_truncated
        else None
    )
    return parsed, reason


def analyzer_availability(tool_name: str) -> AnalyzerAvailability:
    """Adapt ``ToolAvailability`` to the analyzer availability contract."""
    availability = resolve_tool(tool_name)
    return AnalyzerAvailability(
        available=availability.available,
        version=availability.version,
        reason=availability.reason,
    )


def tool_version(tool_name: str) -> str | None:
    """Return the probed version of ``tool_name`` if available."""
    return resolve_tool(tool_name).version


def parse_json_output(tool_name: str, stdout: str, stderr: str) -> object:
    """Parse JSON emitted by an external tool, tolerating leading/trailing log noise."""
    text = stdout.strip()
    if not text:
        raise AnalyzerExecutionError(
            f"`{tool_name}` produced no output (stderr: {_stderr_hint(stderr)})"
        )

    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        pass

    # Some tools interleave human-readable lines with a single JSON document.
    for line in reversed(text.splitlines()):
        candidate = line.strip()
        if not candidate.startswith(("{", "[")):
            continue
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, RecursionError):
            continue

    raise AnalyzerExecutionError(
        f"`{tool_name}` returned malformed JSON output (stderr: {_stderr_hint(stderr)})"
    )


def _stderr_hint(stderr: str, limit: int = 300) -> str:
    cleaned = " ".join(stderr.split())
    if not cleaned:
        return "<empty>"
    return cleaned[:limit]


def untrusted_config_message(
    context: RepositoryContext, config_names: frozenset[str]
) -> str | None:
    """Describe repository tool configuration that RepoLens deliberately does not load."""
    present = select_config_files(context, config_names)
    if not present:
        return None
    joined = ", ".join(present)
    return (
        f"Repository tool configuration ({joined}) was not loaded; "
        "the tool ran with RepoLens' hardened configuration."
    )
