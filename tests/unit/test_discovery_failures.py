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
from repolens.discovery import discover_repository
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
