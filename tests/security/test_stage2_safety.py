"""Security regression tests for Stage 2 analyzers, external tools, and OSV plumbing.

These tests assert the boundary that matters most for RepoLens: a scan of an
attacker-controlled repository must never execute or install target code, must never
trust repository tool configuration, and must never leak secrets into reports.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from repolens.analyzers import default_analyzers
from repolens.config import ScanConfig
from repolens.engine import ScanEngine
from repolens.models import AnalyzerStatus


def _write(root: Path, relative: str, content: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _hostile_repo(root: Path, markers_dir: Path) -> Path:
    """Create a repository whose files would create markers if any code were executed."""
    marker = markers_dir / "executed"

    def touches() -> str:
        return f"open({str(marker)!r}, 'a').write('x')\n"

    root.mkdir(parents=True, exist_ok=True)
    _write(root, "LICENSE", "MIT License\n")
    _write(root, "README.md", "# Hostile\n")
    _write(root, ".gitignore", "__pycache__/\n.venv/\n.env\n")
    _write(root, "pyproject.toml", '[project]\nname = "hostile"\nversion = "1.0.0"\n')
    _write(root, "setup.py", f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n")
    _write(root, "conftest.py", touches())
    _write(root, "tests/test_marker.py", "M = 1\n" + touches())
    _write(root, "app.py", "import os\n\nprint('hello')\n")
    _write(root, "src/app.js", "export const value = 1;\n")
    _write(
        root,
        "package.json",
        json.dumps(
            {
                "name": "hostile",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": f"touch {marker}",
                    "test": f"touch {marker}",
                    "prepare": f"touch {marker}",
                },
            }
        ),
    )
    _write(root, "requirements.txt", "-e .\n")
    return root


def _install_noop_tools(install_fake_tool: Callable[..., Path], log: Path | None = None) -> None:
    """Install stub ruff/bandit/biome executables that never touch the repository."""
    logger = f"append_args({str(log)!r})\n" if log is not None else ""
    install_fake_tool("ruff", f"{logger}emit([])\n", version="ruff 0.9.7")
    install_fake_tool("bandit", f'{logger}emit({{"results": []}})\n', version="bandit 1.9.0")
    install_fake_tool("biome", f'{logger}emit({{"diagnostics": []}})\n', version="Version: 2.6.3")


def _snapshot(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}


def test_scan_never_executes_or_installs_target_code(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    markers = tmp_path / "markers"
    markers.mkdir()
    repo = _hostile_repo(tmp_path / "hostile", markers)
    _install_noop_tools(install_fake_tool)
    before = _snapshot(repo)

    report = ScanEngine().scan(repo)

    assert not (markers / "executed").exists()
    assert not (repo / "node_modules").exists()
    assert not (repo / ".venv").exists()
    assert _snapshot(repo) == before
    statuses = {outcome.analyzer_name: outcome.status for outcome in report.analyzer_outcomes}
    assert statuses["ruff-python-lint"] == AnalyzerStatus.COMPLETED
    assert statuses["bandit-python-security"] == AnalyzerStatus.COMPLETED
    assert statuses["biome-jsts-lint"] == AnalyzerStatus.COMPLETED


def test_tool_arguments_never_contain_shell_or_package_install_commands(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    arg_log = tmp_path / "args.log"
    repo = _hostile_repo(tmp_path / "hostile", tmp_path / "markers2")
    _install_noop_tools(install_fake_tool, log=arg_log)

    ScanEngine().scan(repo)

    logged = arg_log.read_text(encoding="utf-8").splitlines()
    assert logged, "expected the stub tools to be invoked"
    forbidden = {
        "install",
        "pip",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "sh",
        "bash",
        "-c",
        "--fix",
        "--write",
        "eval",
        "exec",
    }
    assert not (set(logged) & forbidden)
    assert all(";" not in token and "&&" not in token for token in logged)


def test_repository_tool_configuration_is_never_loaded(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    arg_log = tmp_path / "args.log"
    repo = _hostile_repo(tmp_path / "hostile", tmp_path / "markers3")
    _write(repo, ".ruff.toml", 'extend = "/etc/passwd"\n[lint]\nselect = []\n')
    _write(repo, ".bandit", "skips: ['*']\n")
    _write(repo, "biome.json", json.dumps({"plugins": ["https://evil.example/grit"]}))
    _install_noop_tools(install_fake_tool, log=arg_log)

    ScanEngine().scan(repo)

    logged = arg_log.read_text(encoding="utf-8").splitlines()
    assert "--isolated" in logged
    for token in logged:
        if token.startswith("--config-path="):
            config_path = Path(token.split("=", 1)[1])
            assert not config_path.is_relative_to(repo.resolve())
        else:
            assert ".ruff.toml" not in token
            assert ".bandit" not in token
            assert token != "--configfile"
            assert token != "-c"
            assert not token.endswith("biome.json")


def test_symlinked_files_are_never_passed_to_external_tools(
    tmp_path: Path,
    install_fake_tool: Callable[..., Path],
    make_symlink: Callable[..., Path],
) -> None:
    arg_log = tmp_path / "args.log"
    repo = tmp_path / "symlinked"
    repo.mkdir()
    _write(repo, "app.py", "x = 1\n")
    outside = tmp_path / "outside_app.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    make_symlink(repo / "link.py", outside)
    _install_noop_tools(install_fake_tool, log=arg_log)

    ScanEngine().scan(repo)

    logged = arg_log.read_text(encoding="utf-8").splitlines()
    assert logged
    assert not any(token.endswith("link.py") for token in logged)


def test_tool_secrets_never_reach_report_messages(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    token = "ghp_" + "D" * 32
    install_fake_tool(
        "ruff",
        f'sys.stderr.write("fatal: leaked {token}\\n")\nraise SystemExit(2)\n',
        version="ruff 0.9.7",
    )
    repo = tmp_path / "leaky"
    repo.mkdir()
    _write(repo, "app.py", "import os\n")

    report = ScanEngine().scan(repo)
    serialized = report.model_dump_json()

    assert token not in serialized
    assert "REDACTED" in serialized
    outcomes = {item.analyzer_name: item for item in report.analyzer_outcomes}
    assert outcomes["ruff-python-lint"].status == AnalyzerStatus.FAILED


def test_truncated_tool_output_is_reported_without_crashing(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    install_fake_tool(
        "ruff",
        'sys.stdout.write(\'[{"code": "F401"\' * 400)\n',
        version="ruff 0.9.7",
    )
    repo = tmp_path / "noisy"
    repo.mkdir()
    _write(repo, "app.py", "import os\n")

    config = ScanConfig(subprocess_max_output_bytes=4096)
    report = ScanEngine(
        config=config, analyzers=[a for a in default_analyzers() if a.name == "ruff-python-lint"]
    ).scan(repo)

    assert report.analyzer_outcomes[0].status == AnalyzerStatus.FAILED
    assert report.findings == []


def test_deeply_nested_manifests_do_not_crash_the_scan(tmp_path: Path) -> None:
    repo = tmp_path / "nested"
    repo.mkdir()
    depth = 2000
    payload = '{"a":' * depth + "1" + "}" * depth
    _write(repo, "package.json", payload)
    _write(repo, "package-lock.json", payload)

    report = ScanEngine().scan(repo)

    # Parsing depth limits differ between CPython versions. When parsing cannot finish,
    # the dependency analyzer must report the gap rather than claiming completeness.
    allowed = {AnalyzerStatus.COMPLETED, AnalyzerStatus.SKIPPED, AnalyzerStatus.UNAVAILABLE}
    for outcome in report.analyzer_outcomes:
        if (
            outcome.analyzer_name == "dependency-manifests"
            and outcome.status is AnalyzerStatus.FAILED
        ):
            assert "dependency inventory incomplete" in (outcome.message or "").lower()
            assert any(f.rule_id == "RL-DEP-001" for f in report.findings)
        else:
            assert outcome.status in allowed
        message = (outcome.message or "").lower()
        assert "recursionerror" not in message
        assert "maximum recursion" not in message


def test_osv_client_receives_only_coordinates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolens.analyzers.advisories import OsvVulnerabilityAnalyzer
    from repolens.osv import OsvPackage, OsvVulnerability

    received: list[OsvPackage] = []

    class CapturingClient:
        def query(self, packages: Sequence[OsvPackage]) -> list[OsvVulnerability]:
            received.extend(packages)
            return []

    repo = tmp_path / "coords"
    repo.mkdir()
    token = "ghp_" + "E" * 30
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (repo / f"{token}.py").write_text("x = 1\n", encoding="utf-8")

    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=lambda cfg: CapturingClient())],
    ).scan(repo)

    assert report.analyzer_outcomes[0].status == AnalyzerStatus.COMPLETED
    assert [(pkg.name, pkg.version, pkg.ecosystem) for pkg in received] == [
        ("requests", "2.31.0", "PyPI")
    ]
    for package in received:
        assert package.name.isprintable()
        assert "/" not in package.name
        assert token not in package.name


def test_sanitized_environment_is_used_for_tool_invocations(
    tmp_path: Path, install_fake_tool: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "AIza" + "F" * 35)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "G" * 32)
    env_log = tmp_path / "env.log"
    install_fake_tool(
        "ruff",
        f"Path({str(env_log)!r}).write_text("
        "'\\n'.join(key for key in ('GEMINI_API_KEY', 'GITHUB_TOKEN') if key in os.environ), "
        "encoding='utf-8')\n"
        "emit([])\n",
        version="ruff 0.9.7",
    )
    repo = tmp_path / "env"
    repo.mkdir()
    _write(repo, "app.py", "import os\n")

    ScanEngine(analyzers=[a for a in default_analyzers() if a.name == "ruff-python-lint"]).scan(
        repo
    )

    assert env_log.exists()
    assert env_log.read_text(encoding="utf-8") == ""
    assert os.environ.get("GEMINI_API_KEY") is not None
