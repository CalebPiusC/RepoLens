"""Regression tests: discovery must report, never silently swallow, filesystem failures.

A scan that cannot see part of a repository has to say so, because otherwise a missing
high-severity finding turns into a green CI run. These tests cover the walker counters and
the propagation of those counters into the scan report, deterministically where possible
and with a real permission error where the platform permits it.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from repolens.config import ScanConfig
from repolens.discovery import MAX_DIRECTORY_DEPTH, discover_repository
from repolens.engine import ScanEngine
from repolens.exceptions import DiscoveryAbortedError


class _UnreadableEntry:
    """DirEntry stand-in whose metadata lookups fail like a permission-denied file."""

    def __init__(self, directory: Path, name: str) -> None:
        self.name = name
        self.path = str(directory / name)

    def is_symlink(self) -> bool:
        return False

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        return False

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        return True

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        raise PermissionError(13, "Permission denied")


class _ScandirProxy:
    """Context-manager wrapper around a list of entries, mimicking ``os.scandir``."""

    def __init__(self, entries: list[object]) -> None:
        self._entries = entries

    def __enter__(self) -> list[object]:
        return self._entries

    def __exit__(self, *exc_info: object) -> None:
        return None


@pytest.fixture
def small_repo(tmp_path: Path) -> Callable[..., Path]:
    def _create(name: str = "repo") -> Path:
        root = tmp_path / name
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "core.py").write_text("x = 1\n", encoding="utf-8")
        (root / "README.md").write_text("# repo\n", encoding="utf-8")
        return root

    return _create


def test_unreadable_directory_is_counted(
    small_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An OSError from ``os.scandir`` must be recorded, not silently skipped."""
    repo = small_repo()
    locked = repo / "locked"
    locked.mkdir()
    real_scandir = os.scandir

    def _scandir(path: str | os.PathLike[str]) -> Iterator[os.DirEntry[str]]:
        if Path(path).name == "locked":
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr("repolens.discovery.os.scandir", _scandir)

    context = discover_repository(repo, ScanConfig())

    assert context.summary.unreadable_directory_count == 1
    assert context.summary.unreadable_entry_count == 0
    assert context.summary.has_discovery_failures is True
    assert context.summary.is_partial is True
    # The readable part of the tree was still discovered.
    assert context.has_file("pkg/core.py")
    assert context.has_file("README.md")


def test_unreadable_directory_propagates_to_the_scan_report(
    small_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The engine must carry the failure through to ``ScanReport.discovery``."""
    repo = small_repo()
    (repo / "locked").mkdir()
    real_scandir = os.scandir

    def _scandir(path: str | os.PathLike[str]) -> Iterator[os.DirEntry[str]]:
        if Path(path).name == "locked":
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr("repolens.discovery.os.scandir", _scandir)

    report = ScanEngine().scan(repo)

    assert report.discovery.unreadable_directory_count == 1
    assert report.discovery.is_partial is True


def test_unreadable_entry_is_counted(
    small_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single entry whose stat/resolve fails is recorded as an unreadable entry."""
    repo = small_repo()
    real_scandir = os.scandir

    def _scandir(path: str | os.PathLike[str]) -> _ScandirProxy:
        entries: list[object] = list(real_scandir(path))
        if Path(path) == repo:
            entries.append(_UnreadableEntry(repo, "secret.py"))
        return _ScandirProxy(entries)

    monkeypatch.setattr("repolens.discovery.os.scandir", _scandir)

    context = discover_repository(repo, ScanConfig())

    assert context.summary.unreadable_entry_count == 1
    assert context.summary.unreadable_directory_count == 0
    assert context.summary.has_discovery_failures is True
    assert not context.has_file("secret.py")


def test_readable_repository_reports_no_discovery_failures(small_repo: Callable[..., Path]) -> None:
    context = discover_repository(small_repo(), ScanConfig())

    assert context.summary.unreadable_directory_count == 0
    assert context.summary.unreadable_entry_count == 0
    assert context.summary.is_partial is False


def test_mid_walk_escape_raises_discovery_aborted(
    small_repo: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A security abort after the walk started is distinct from a pre-scan rejection."""
    repo = small_repo()
    victim = repo / "pkg" / "core.py"
    real_resolve = Path.resolve

    def _resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self == victim:
            return Path("/etc/passwd")
        return real_resolve(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("repolens.discovery.Path.resolve", _resolve)

    with pytest.raises(DiscoveryAbortedError, match="escaped canonical root"):
        discover_repository(repo, ScanConfig())


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses directory permissions",
)
def test_unreadable_directory_permission_error_is_detected(
    small_repo: Callable[..., Path],
) -> None:
    """End-to-end with real filesystem permissions, where the platform enforces them."""
    repo = small_repo()
    locked = repo / "locked"
    locked.mkdir()
    (locked / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    locked.chmod(0o000)
    try:
        try:
            list(os.scandir(locked))
        except PermissionError:
            pass
        else:  # pragma: no cover - platform dependent (ACLs, containers, root)
            pytest.skip("this platform does not enforce directory permissions")

        context = discover_repository(repo, ScanConfig())
    finally:
        locked.chmod(stat.S_IRWXU)

    assert context.summary.unreadable_directory_count == 1
    assert context.summary.is_partial is True
    assert not context.has_file("locked/broken.py")


def test_scan_config_limits_mark_discovery_partial(tmp_path: Path) -> None:
    """File/byte caps are partial discovery too, and stay distinguishable from failures."""
    repo = tmp_path / "many"
    repo.mkdir()
    for index in range(6):
        (repo / f"f_{index}.py").write_text("x = 1\n" * 200, encoding="utf-8")

    capped = discover_repository(repo, ScanConfig(max_files=3))

    assert capped.summary.truncated_by_file_limit is True
    assert capped.summary.has_discovery_failures is False
    assert capped.summary.is_partial is True


# --------------------------------------------------------------------------------------
# Nesting-depth limit
# --------------------------------------------------------------------------------------


def _bury(root: Path, depth: int) -> Path:
    """Nest to exactly ``depth`` levels below ``root`` and return the unreachable subtree.

    The walker stops pushing subdirectories once it reaches ``MAX_DIRECTORY_DEPTH``, so the
    returned directory is the first one it refuses to enter.
    """
    current = root
    for index in range(depth):
        current = current / f"d{index}"
    current.mkdir(parents=True)
    buried = current / "buried"
    buried.mkdir()
    (buried / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    return buried


def test_directories_beyond_the_depth_limit_are_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A subtree skipped for exceeding MAX_DIRECTORY_DEPTH must be reported, not dropped."""
    monkeypatch.setattr("repolens.discovery.MAX_DIRECTORY_DEPTH", 3)
    repo = tmp_path / "deep"
    repo.mkdir()
    (repo / "shallow.py").write_text("x = 1\n", encoding="utf-8")
    _bury(repo, 3)

    context = discover_repository(repo, ScanConfig())

    assert context.summary.skipped_by_depth_count == 1
    assert context.summary.depth_limited is True
    assert context.summary.is_partial is True
    assert context.has_file("shallow.py")
    assert not context.has_file("d0/d1/d2/buried/broken.py")


def test_depth_limit_is_not_flagged_for_shallow_repositories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("repolens.discovery.MAX_DIRECTORY_DEPTH", 64)
    repo = tmp_path / "shallow"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "core.py").write_text("x = 1\n", encoding="utf-8")

    context = discover_repository(repo, ScanConfig())

    assert context.summary.skipped_by_depth_count == 0
    assert context.summary.depth_limited is False
    assert context.summary.is_partial is False


def test_depth_limit_reaches_the_scan_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("repolens.discovery.MAX_DIRECTORY_DEPTH", 2)
    repo = tmp_path / "deep-report"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    _bury(repo, 2)

    report = ScanEngine().scan(repo)

    assert report.discovery.skipped_by_depth_count == 1
    assert report.discovery.is_partial is True


def test_depth_limited_scan_is_incomplete_but_findings_still_win(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit-code policy for depth-limited discovery: 3 when clean, 1 when findings exist."""
    from repolens.cli import EXIT_FINDINGS, EXIT_OPERATIONAL, determine_exit_code
    from repolens.models import (
        AnalyzerOutcome,
        AnalyzerStatus,
        Category,
        Confidence,
        Finding,
        FindingSource,
        Severity,
        SourceKind,
    )

    monkeypatch.setattr("repolens.discovery.MAX_DIRECTORY_DEPTH", 1)
    repo = tmp_path / "deep-exit"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    _bury(repo, 1)

    report = ScanEngine().scan(repo)
    assert report.discovery.skipped_by_depth_count == 1

    # Nothing above the threshold: an incomplete scan must not look clean.
    assert determine_exit_code(report, Severity.CRITICAL) == EXIT_OPERATIONAL

    finding = Finding(
        rule_id="RL-X-001",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        title="critical issue",
        explanation="explanation",
        recommendation="recommendation",
        verification="verification",
        source=FindingSource(kind=SourceKind.DETERMINISTIC, tool="test"),
    )
    with_findings = report.model_copy(
        update={
            "findings": [finding],
            "analyzer_outcomes": [
                AnalyzerOutcome(analyzer_name="test", status=AnalyzerStatus.COMPLETED)
            ],
        }
    )
    assert determine_exit_code(with_findings, Severity.CRITICAL) == EXIT_FINDINGS


# --------------------------------------------------------------------------------------
# Other deliberate skips
# --------------------------------------------------------------------------------------


def test_excluded_directories_are_counted_but_do_not_make_a_scan_incomplete(
    tmp_path: Path,
) -> None:
    """Convention-based exclusions (.git, node_modules, dist, ...) stay intentional."""
    repo = tmp_path / "with-excluded"
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "index.js").write_text("x\n", encoding="utf-8")
    (repo / "dist").mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")

    context = discover_repository(repo, ScanConfig())

    assert context.summary.skipped_excluded_count == 2
    assert context.summary.is_partial is False
    assert not context.has_file("node_modules/pkg/index.js")


def test_oversized_files_are_counted_but_do_not_make_a_scan_incomplete(tmp_path: Path) -> None:
    repo = tmp_path / "oversized"
    repo.mkdir()
    (repo / "big.py").write_text("x = 1\n" * 500, encoding="utf-8")

    context = discover_repository(repo, ScanConfig(max_file_size_bytes=1024))

    assert context.summary.skipped_oversized_count == 1
    assert context.summary.is_partial is False


def test_nesting_beyond_the_production_limit_is_reported(
    short_root: Path, make_nested_directories: Callable[..., Path]
) -> None:
    """Use the real MAX_DIRECTORY_DEPTH: no monkeypatching of the limit."""
    repo = short_root / "deep-real"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    # One directory per level, plus a final directory that the walker must refuse.
    deepest = make_nested_directories(repo, MAX_DIRECTORY_DEPTH, leaf=("unreachable",))
    (deepest / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    context = discover_repository(repo, ScanConfig())

    assert context.summary.skipped_by_depth_count == 1
    assert context.summary.is_partial is True
    assert context.has_file("app.py")
    assert not context.has_file("/".join(["d"] * MAX_DIRECTORY_DEPTH + ["unreachable/broken.py"]))
