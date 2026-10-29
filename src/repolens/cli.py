"""Command-line interface for RepoLens.

The CLI is a thin, well-behaved shell around :class:`repolens.engine.ScanEngine`: it
parses arguments, applies :class:`repolens.config.ScanConfig` options, renders the
resulting :class:`~repolens.models.ScanReport`, and maps the outcome to a documented
exit code. It deliberately implements no analysis of its own, so path validation,
symlink handling, resource limits, secret redaction, and analyzer isolation are exactly
the ones the library enforces.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final, TextIO

from repolens import __version__
from repolens.config import ScanConfig
from repolens.engine import ScanEngine
from repolens.exceptions import DiscoveryAbortedError, DiscoveryError, RepoLensError
from repolens.json_output import render_json
from repolens.models import ScanReport, Severity
from repolens.redaction import redact_secrets
from repolens.reporting import RenderOptions, evaluate, render_report

# Exit-code policy. Documented in the README and in `repolens --help`.
EXIT_OK: Final = 0
"""Scan completed and no finding met the configured severity threshold."""

EXIT_FINDINGS: Final = 1
"""Scan completed and at least one finding met the configured severity threshold."""

EXIT_USAGE: Final = 2
"""Invalid arguments, or the target path is missing, not a directory, or unsafe."""

EXIT_OPERATIONAL: Final = 3
"""The scan could not be completed: analyzer failure/timeout, incomplete discovery, or an
internal error. Never returned for a scan that covered the whole repository."""

EXIT_INTERRUPTED: Final = 130
"""The scan was interrupted (Ctrl-C), matching shell conventions for SIGINT."""

_ISSUE_URL: Final = "https://github.com/CalebPiusC/RepoLens/issues"
_SEVERITY_CHOICES: Final[tuple[str, ...]] = tuple(
    severity.value for severity in reversed(list(Severity))
)
_MAX_FINDINGS_CEILING: Final = 10_000

_EPILOG: Final = """\
exit codes:
  0  scan completed, no findings at or above the severity threshold
  1  scan completed, findings at or above the severity threshold were detected
  2  invalid arguments or unusable target path (nothing was scanned)
  3  scan could not be completed: an analyzer failed or timed out, discovery could
     not read the whole repository, or an internal error occurred
  130  scan interrupted (Ctrl-C)

Exit codes 2 and 3 both mean "do not trust a clean result"; only 0 means clean.

Output formats:
  text   human-readable report with an analyzer table and a summary (default)
  json   one machine-readable JSON document on stdout, with no color and no progress
         text; diagnostics still go to stderr and the exit codes above are unchanged

RepoLens is a static analyzer: it never executes code, installs dependencies, or runs
test suites from the repository it scans.
"""

_EXAMPLES: Final = """\
examples:
  repolens scan .                 scan the current directory
  repolens scan ../my-service     scan a specific project directory
  repolens scan . --min-severity high
                                  only fail on high or critical findings
  repolens scan . --network-checks
                                  enable optional OSV.dev vulnerability lookups
  repolens scan . --format json   machine-readable output for CI and tooling
"""


class _UsageError(Exception):
    """Raised for argument combinations argparse cannot express."""


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {raw!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or greater")
    if value > _MAX_FINDINGS_CEILING:
        raise argparse.ArgumentTypeError(f"must be {_MAX_FINDINGS_CEILING} or less")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="repolens",
        description=(
            "Static repository health checker for Python and JavaScript/TypeScript projects. "
            "Scans code, manifests, dependencies, documentation, and tests without executing "
            "or installing anything from the target repository."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show the RepoLens version and exit",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
        title="commands",
    )
    scan_parser = subparsers.add_parser(
        "scan",
        help="scan a project directory and report findings",
        description=(
            "Scan a project directory. Static analyzers inspect the files in place; no "
            "repository code is executed and no dependencies are installed."
        ),
        epilog=_EXAMPLES + "\n" + _EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        metavar="PATH",
        help="directory to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=_SEVERITY_CHOICES,
        default=Severity.INFO.value,
        metavar="{info,low,medium,high,critical}",
        help="only findings at or above this severity affect the exit code and the result "
        "line; every finding is still counted in the summary (default: info)",
    )
    scan_parser.add_argument(
        "--max-findings",
        type=_positive_int,
        default=50,
        metavar="N",
        help="maximum number of findings to print, 1-10000 (default: 50)",
    )
    scan_parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="colorize output; auto enables color only on a terminal (default: auto)",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        metavar="{text,json}",
        help="output format: 'text' for the human-readable report, 'json' for one "
        "machine-readable document on stdout (always complete, never colorized) "
        "(default: text)",
    )
    scan_parser.add_argument(
        "--network-checks",
        action="store_true",
        help="enable optional OSV.dev known-vulnerability lookups for locked dependencies "
        "(network access required; disabled by default)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code.

    ``argparse`` exits through ``SystemExit`` for ``--help``/``--version`` and usage
    errors; those codes are returned instead so callers (and tests) always get an int.
    ``KeyboardInterrupt`` is handled once, here, so an interrupt anywhere in parsing,
    option resolution, scanning, rendering, or output behaves the same way.
    """
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("\nrepolens: interrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED


def _main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE

    if args.command != "scan":
        # No command supplied: show help but signal that nothing was scanned.
        parser.print_help(sys.stdout)
        return EXIT_USAGE

    try:
        command = _scan_command(args)
    except _UsageError as exc:
        print(f"repolens: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return command.run(stdout=sys.stdout, stderr=sys.stderr)


class _ScanCommand:
    """Resolved, validated options for a single `repolens scan` invocation."""

    def __init__(
        self,
        *,
        target: Path,
        config: ScanConfig,
        options: RenderOptions,
        color_mode: str,
        output_format: str,
    ) -> None:
        self.target = target
        self.config = config
        self.options = options
        self.color_mode = color_mode
        self.output_format = output_format

    def run(self, *, stdout: TextIO, stderr: TextIO) -> int:
        """Execute the scan, print the report, and return the exit code."""
        try:
            return self._run(stdout=stdout, stderr=stderr)
        except KeyboardInterrupt:
            # Ctrl-C during rendering or output must behave like Ctrl-C during the scan.
            print("\nrepolens: scan interrupted.", file=stderr)
            return EXIT_INTERRUPTED

    def _run(self, *, stdout: TextIO, stderr: TextIO) -> int:
        try:
            report = ScanEngine(config=self.config).scan(self.target)
        except DiscoveryAbortedError as exc:
            # Discovery started and then refused to continue, so scanning did happen:
            # this is an operational failure, not a "nothing was scanned" usage error.
            print(f"repolens: error: scan aborted part-way: {_safe(exc)}", file=stderr)
            return EXIT_OPERATIONAL
        except DiscoveryError as exc:
            print(f"repolens: error: {_safe(exc)}", file=stderr)
            return EXIT_USAGE
        except RepoLensError as exc:
            print(f"repolens: error: {_safe(exc)}", file=stderr)
            return EXIT_OPERATIONAL
        except Exception as exc:
            print(f"repolens: internal error: {_safe_unexpected(exc)}", file=stderr)
            print(
                f"repolens: this is a RepoLens bug; please report it at {_ISSUE_URL}",
                file=stderr,
            )
            return EXIT_OPERATIONAL

        exit_code = determine_exit_code(report, self.options.min_severity)
        if self.output_format == "json":
            # Machine output: exactly one JSON document on stdout. No color, no banner, no
            # analyzer table, and no ``--max-findings`` truncation (see repolens.json_output).
            print(
                render_json(
                    report,
                    exit_code=exit_code,
                    min_severity=self.options.min_severity,
                ),
                file=stdout,
            )
            return exit_code

        options = RenderOptions(
            color=_use_color(self.color_mode, stdout),
            min_severity=self.options.min_severity,
            max_findings=self.options.max_findings,
        )
        print(
            render_report(
                report,
                options=options,
                target_path=str(self.target),
                exit_code=exit_code,
            ),
            file=stdout,
        )
        return exit_code


def _scan_command(args: argparse.Namespace) -> _ScanCommand:
    raw_path = args.path
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise _UsageError("PATH must be a non-empty directory path")
    if "\x00" in raw_path:
        raise _UsageError("PATH must not contain NUL bytes")

    min_severity = Severity(args.min_severity)
    return _ScanCommand(
        target=Path(raw_path).expanduser(),
        config=ScanConfig(enable_network_checks=bool(args.network_checks)),
        options=RenderOptions(
            min_severity=min_severity,
            max_findings=int(args.max_findings),
        ),
        color_mode=str(args.color),
        output_format=str(args.format),
    )


def determine_exit_code(report: ScanReport, min_severity: Severity = Severity.INFO) -> int:
    """Map a completed scan to its documented exit code.

    Findings take precedence over incompleteness because they are directly actionable.
    Otherwise an incomplete scan — a failed/timed-out analyzer, discovery that stopped at a
    resource limit, or directories/entries that could not be read — returns
    ``EXIT_OPERATIONAL`` rather than ``EXIT_OK``, so partial coverage is never reported as
    clean. Only ``UNAVAILABLE`` (optional tool missing) and ``SKIPPED`` analyzers leave the
    exit code untouched.
    """
    verdict = evaluate(report, min_severity)
    if verdict.has_findings:
        return EXIT_FINDINGS
    if verdict.is_incomplete:
        return EXIT_OPERATIONAL
    return EXIT_OK


def _use_color(mode: str, stream: TextIO) -> bool:
    """Decide whether ANSI styling is appropriate for ``stream``."""
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _safe(exc: BaseException) -> str:
    """Return a scrubbed, single-line error message suitable for a terminal."""
    return redact_secrets(" ".join(str(exc).split()) or type(exc).__name__, max_length=500)


def _safe_unexpected(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {_safe(exc)}"


if __name__ == "__main__":  # pragma: no cover - exercised through the entry point
    sys.exit(main())


__all__ = [
    "EXIT_FINDINGS",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "EXIT_OPERATIONAL",
    "EXIT_USAGE",
    "build_parser",
    "determine_exit_code",
    "main",
]
