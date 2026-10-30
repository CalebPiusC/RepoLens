"""Unit tests for external tool probing, bounded execution, and path mapping."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from repolens.analyzers.base import (
    AnalyzerExecutionError,
    AnalyzerTimeoutError,
    AnalyzerUnavailableError,
)
from repolens.analyzers.tooling import (
    absolute_paths,
    analyzer_availability,
    clear_tool_cache,
    iter_batches,
    parse_json_output,
    probe_tool,
    repository_relative_path,
    resolve_tool,
    run_tool,
    select_source_files,
    select_source_files_with_status,
    tool_workspace,
    untrusted_config_message,
)
from repolens.config import ScanConfig
from repolens.discovery import discover_repository


def test_probe_tool_detects_executable_and_version(
    install_fake_tool: Callable[..., Path],
) -> None:
    install_fake_tool("ruff", "pass\n", version="ruff 0.9.7")

    availability = probe_tool("ruff")
    assert availability.available is True
    assert availability.version == "0.9.7"
    assert availability.executable is not None


def test_probe_tool_reports_missing_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    clear_tool_cache()

    availability = resolve_tool("definitely-not-installed-tool")
    assert availability.available is False
    assert "not found on PATH" in (availability.reason or "")
    assert analyzer_availability("definitely-not-installed-tool").available is False


def test_probe_tool_rejects_invalid_name() -> None:
    availability = probe_tool("../evil")
    assert availability.available is False
    assert availability.reason == "Invalid tool name."


def test_probe_tool_tolerates_version_failure(
    install_fake_tool: Callable[..., Path],
) -> None:
    install_fake_tool("odd-tool", "raise SystemExit(3)\n")
    availability = probe_tool("odd-tool")
    assert availability.available is True
    assert availability.version is None


def test_run_tool_requires_available_executable(tmp_path: Path) -> None:
    with tool_workspace() as workspace, pytest.raises(AnalyzerUnavailableError):
        run_tool(
            "definitely-not-installed-tool",
            ["--version"],
            cwd=workspace,
            timeout_seconds=1.0,
            max_output_bytes=4096,
        )


def test_run_tool_maps_timeout_to_analyzer_timeout(
    install_fake_tool: Callable[..., Path],
) -> None:
    install_fake_tool("sleepy-tool", "time.sleep(30)\n")
    with tool_workspace() as workspace, pytest.raises(AnalyzerTimeoutError, match="exceeded"):
        run_tool(
            "sleepy-tool",
            [],
            cwd=workspace,
            timeout_seconds=0.3,
            max_output_bytes=4096,
        )


def test_run_tool_passes_structured_arguments(
    install_fake_tool: Callable[..., Path], tmp_path: Path
) -> None:
    marker = tmp_path / "args.txt"
    install_fake_tool(
        "echo-tool",
        f"Path({str(marker)!r}).write_text('\\n'.join(_args) + '\\n', encoding='utf-8')\n",
    )
    with tool_workspace() as workspace:
        result = run_tool(
            "echo-tool",
            ["--flag", "value with spaces", "a;b"],
            cwd=workspace,
            timeout_seconds=10.0,
            max_output_bytes=4096,
        )
    assert result.returncode == 0
    assert marker.read_text(encoding="utf-8").splitlines() == [
        "--flag",
        "value with spaces",
        "a;b",
    ]


def test_iter_batches_is_deterministic() -> None:
    assert [list(batch) for batch in iter_batches(["a", "b", "c"], 2)] == [
        ["a", "b"],
        ["c"],
    ]
    assert [list(batch) for batch in iter_batches([], 5)] == []
    assert [list(batch) for batch in iter_batches(["x"], 0)] == [["x"]]


def test_repository_relative_path_handles_absolute_relative_and_escapes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    cwd = tmp_path / "workspace"
    cwd.mkdir()
    target = root / "src" / "app.py"
    target.parent.mkdir()
    target.write_text("x = 1\n", encoding="utf-8")

    assert repository_relative_path(str(target), root=root, cwd=cwd) == "src/app.py"
    relative_report = os.path.relpath(target, cwd)
    assert repository_relative_path(relative_report, root=root, cwd=cwd) == "src/app.py"
    assert repository_relative_path(str(tmp_path / "outside.py"), root=root, cwd=cwd) is None
    assert repository_relative_path("", root=root, cwd=cwd) is None


def test_absolute_paths_rejects_traversal(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    paths = absolute_paths(root, ["a.py", "../escape.py", "/etc/passwd", ""])
    assert paths == [str(root / "a.py")]


def test_select_source_files_skips_sensitive_oversized_and_ignored(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    (repo / ".env").write_text("TOKEN=abc\n", encoding="utf-8")
    (repo / "ignored.py").write_text("x = 1\n", encoding="utf-8")
    with (repo / ".gitignore").open("a", encoding="utf-8") as handle:
        handle.write("ignored.py\n")

    config = ScanConfig(max_file_size_bytes=1024)
    context = discover_repository(repo, config)
    selected = select_source_files(context, frozenset({".py"}), limit=50)
    assert "src/sample/core.py" in selected
    assert "ignored.py" not in selected
    assert ".env" not in selected


def test_untrusted_config_message_reports_present_config(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    context = discover_repository(repo, ScanConfig())
    assert untrusted_config_message(context, frozenset({"biome.json"})) is None

    (repo / "biome.json").write_text("{}", encoding="utf-8")
    context = discover_repository(repo, ScanConfig())
    message = untrusted_config_message(context, frozenset({"biome.json"}))
    assert message is not None
    assert "not loaded" in message


def test_parse_json_output_handles_noise_and_rejects_garbage() -> None:
    assert parse_json_output("tool", '{"a": 1}', "") == {"a": 1}
    assert parse_json_output("tool", 'warning: deprecated\n{"a": 1}\n', "") == {"a": 1}

    with pytest.raises(AnalyzerExecutionError, match="no output"):
        parse_json_output("tool", "   ", "boom")

    with pytest.raises(AnalyzerExecutionError, match="malformed"):
        parse_json_output("tool", "not json at all", "boom")


def test_tool_workspace_is_disposable_and_outside_repository(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo().resolve()
    with tool_workspace() as workspace:
        path = workspace
        assert workspace.exists()
        assert not workspace.is_relative_to(repo)
    assert not path.exists()


def test_tool_probe_never_executes_repository_commands(
    install_fake_tool: Callable[..., Path], tmp_path: Path
) -> None:
    marker = tmp_path / "marker"
    (tmp_path / "setup.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    install_fake_tool("probe-tool", "pass\n", version="1.2.3")
    probe_tool("probe-tool")
    assert not marker.exists()
    assert os.environ.get("PATH", "").startswith(str(tmp_path / "fake-bin"))


def test_select_source_files_with_status_reports_the_limit(tmp_path: Path) -> None:
    repo = tmp_path / "many"
    repo.mkdir()
    for index in range(3):
        (repo / f"m{index}.py").write_text("x = 1\n", encoding="utf-8")
    context = discover_repository(repo, ScanConfig())

    exactly, exact_truncated = select_source_files_with_status(context, frozenset({".py"}), limit=3)
    assert len(exactly) == 3
    assert exact_truncated is False

    capped, truncated = select_source_files_with_status(context, frozenset({".py"}), limit=2)
    assert len(capped) == 2
    assert truncated is True

    # The backwards-compatible wrapper keeps the same selection.
    assert select_source_files(context, frozenset({".py"}), limit=2) == capped


def test_probe_tool_returns_an_absolute_path_for_a_relative_path_entry(
    install_fake_tool: Callable[..., Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative `PATH` entry must not yield a relative executable path.

    `shutil.which` returns the relative path verbatim when the matching `PATH` entry is
    relative. Tools are then executed from a different working directory, where that relative
    path no longer resolves, so probing must anchor the path while the current directory is
    still the one `PATH` was interpreted against.

    The scan runs from a directory whose contents are addressed relatively, which is what makes
    the anchoring observable; `os.path.relpath` is avoided because a Windows CI checkout and its
    temporary directory can sit on different drives, where it raises `ValueError`.
    """
    install_fake_tool("relative-tool", "pass\n", version="2.4.6")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join(["fake-bin", os.environ.get("PATH", "")]))
    clear_tool_cache()

    availability = probe_tool("relative-tool")

    assert availability.available is True
    assert availability.executable is not None
    assert Path(availability.executable).is_absolute()
    assert Path(availability.executable).is_file()
    # Anchoring must not lose the version probe, which also runs from a different directory.
    assert availability.version == "2.4.6"
