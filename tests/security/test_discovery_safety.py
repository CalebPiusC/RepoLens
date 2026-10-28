"""Adversarial security tests for repository file discovery and read boundaries."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from repolens.config import ScanConfig
from repolens.discovery import MAX_DIRECTORY_DEPTH, discover_repository
from repolens.exceptions import (
    DiscoveryError,
    OversizedFileAccessError,
    PathSecurityError,
    SensitiveFileAccessError,
)


def test_symlink_escape_files_and_dirs_are_never_followed(
    tmp_path: Path,
    make_python_repo: Callable[..., Path],
    make_symlink: Callable[..., Path],
) -> None:
    outside_dir = tmp_path / "outside_secrets"
    outside_dir.mkdir()
    outside_secret = outside_dir / "host_passwd.txt"
    outside_secret.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")

    repo = make_python_repo()
    make_symlink(repo / "escaped_file.py", outside_secret)
    make_symlink(repo / "escaped_dir", outside_dir, target_is_directory=True)

    context = discover_repository(repo)
    assert context.summary.skipped_symlink_count == 2
    assert set(context.skipped_symlinks) == {"escaped_dir", "escaped_file.py"}
    assert not context.has_file("escaped_file.py")
    assert not context.has_file("escaped_dir/host_passwd.txt")

    with pytest.raises(DiscoveryError):
        context.read_text("escaped_file.py")


def test_symlink_repository_root_is_rejected(
    tmp_path: Path,
    make_python_repo: Callable[..., Path],
    make_symlink: Callable[..., Path],
) -> None:
    real_repo = make_python_repo()
    symlink_root = make_symlink(tmp_path / "repo_link", real_repo, target_is_directory=True)

    with pytest.raises(PathSecurityError, match="symbolic link"):
        discover_repository(symlink_root)


@pytest.mark.parametrize(
    "malicious_path",
    [
        "../outside.txt",
        "src/../../outside.txt",
        "/etc/hosts",
        "src\\core.py",
        "src/\x00evil.py",
        "",
    ],
)
def test_read_text_blocks_path_traversal(
    make_python_repo: Callable[..., Path],
    malicious_path: str,
) -> None:
    repo = make_python_repo()
    context = discover_repository(repo)
    with pytest.raises(PathSecurityError):
        context.read_text(malicious_path)


def test_read_text_blocks_post_discovery_toctou_symlink_swap(
    tmp_path: Path,
    make_python_repo: Callable[..., Path],
    make_symlink: Callable[..., Path],
) -> None:
    outside = tmp_path / "secret_target.txt"
    outside.write_text("TOP_SECRET\n", encoding="utf-8")

    repo = make_python_repo()
    context = discover_repository(repo)

    # Simulate a TOCTOU swap after discovery completed
    swapped = repo / "src" / "sample" / "core.py"
    swapped.unlink()
    make_symlink(swapped, outside)

    with pytest.raises(PathSecurityError):
        context.read_text("src/sample/core.py")


def test_sensitive_and_oversized_files_cannot_be_read_by_analyzers(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    (repo / ".env").write_text(
        "OPENAI_API_KEY=sk-live-123456789012345678901234\n", encoding="utf-8"
    )
    (repo / "huge.txt").write_bytes(b"A" * 4096)

    context = discover_repository(repo, ScanConfig(max_file_size_bytes=2048))
    assert context.summary.sensitive_files_detected == 1
    assert context.summary.skipped_oversized_count == 1

    with pytest.raises(SensitiveFileAccessError):
        context.read_text(".env")

    with pytest.raises(OversizedFileAccessError):
        context.read_text("huge.txt")


def test_file_count_and_total_byte_limits_and_deep_nesting(
    short_root: Path, make_nested_directories: Callable[..., Path]
) -> None:
    repo = short_root / "bounded_repo"
    repo.mkdir()
    for idx in range(10):
        (repo / f"f_{idx:02d}.py").write_text("x = 1\n" * 100, encoding="utf-8")

    capped_files = discover_repository(repo, ScanConfig(max_files=4))
    assert capped_files.summary.total_files_scanned == 4
    assert capped_files.summary.truncated_by_file_limit is True

    capped_bytes = discover_repository(
        repo, ScanConfig(max_file_size_bytes=2048, max_total_bytes=4096)
    )
    assert capped_bytes.summary.total_bytes_scanned <= 4096
    assert capped_bytes.summary.truncated_by_byte_limit is True

    # Deeply nested directories exceeding MAX_DIRECTORY_DEPTH should not raise RecursionError
    deep = repo / "deep"
    deepest = make_nested_directories(deep, MAX_DIRECTORY_DEPTH + 15)
    (deepest / "unreachable.py").write_text("y = 2\n", encoding="utf-8")

    deep_context = discover_repository(repo)
    assert not any("unreachable.py" in f.path for f in deep_context.files)
