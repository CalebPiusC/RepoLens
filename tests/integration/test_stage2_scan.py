"""Integration tests running the full scan pipeline with stubbed external tools.

The stubs are real executables on a temporary ``PATH``, so these tests exercise the
actual subprocess execution path (argument handling, working directory, JSON parsing,
timeouts) without requiring Ruff, Bandit, or Biome to be installed.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from repolens.analyzers import default_analyzers
from repolens.analyzers.advisories import OsvVulnerabilityAnalyzer
from repolens.config import ScanConfig
from repolens.engine import ScanEngine
from repolens.models import AnalyzerStatus, Confidence, ScanReport, Severity


def _write(root: Path, relative: str, content: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _install_json_tool(
    install_fake_tool: Callable[..., Path],
    name: str,
    version_output: str,
    payload_path: Path,
) -> None:
    install_fake_tool(
        name,
        f"print(Path({str(payload_path)!r}).read_text(encoding='utf-8'))\n",
        version=version_output,
    )


def _python_repo(tmp_path: Path) -> Path:
    root = tmp_path / "python-repo"
    root.mkdir()
    _write(root, "LICENSE", "MIT License\n")
    _write(root, "README.md", "# Demo\n\nSee [the guide](docs/guide.md).\n")
    _write(root, ".gitignore", "__pycache__/\n*.py[codz]\n.venv/\n.env\ndist/\n")
    _write(
        root,
        "pyproject.toml",
        '[project]\nname = "demo"\nversion = "1.0.0"\ndependencies = ["requests>=2.31"]\n',
    )
    _write(root, "src/demo/__init__.py", '"""Demo."""\n')
    _write(root, "src/demo/core.py", "import os\n\n\ndef run(value):\n    return eval(value)\n")
    return root


def _ruff_payload(path: Path) -> list[dict[str, object]]:
    return [
        {
            "code": "F401",
            "message": "`os` imported but unused",
            "filename": str(path),
            "location": {"row": 1, "column": 8},
            "end_location": {"row": 1, "column": 10},
            "name": "unused-import",
            "url": "https://docs.astral.sh/ruff/rules/unused-import",
        },
        {
            "code": "F841",
            "message": "Local variable `unused` is assigned to but never used",
            "filename": str(path),
            "location": {"row": 4, "column": 5},
            "end_location": {"row": 4, "column": 11},
            "name": "unused-variable",
            "url": "https://docs.astral.sh/ruff/rules/unused-variable",
        },
    ]


def test_problematic_python_repository_end_to_end(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    repo = _python_repo(tmp_path)
    core = repo / "src" / "demo" / "core.py"

    ruff_json = tmp_path / "ruff.json"
    ruff_json.write_text(json.dumps(_ruff_payload(core)), encoding="utf-8")
    bandit_json = tmp_path / "bandit.json"
    bandit_json.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "test_id": "B307",
                        "test_name": "blacklist",
                        "issue_severity": "MEDIUM",
                        "issue_confidence": "HIGH",
                        "filename": str(core),
                        "line_number": 5,
                        "issue_text": "Use of possibly insecure function - consider "
                        "using safer ast.literal_eval.",
                        "issue_cwe": {"id": 78},
                        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b307.html",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    _install_json_tool(install_fake_tool, "ruff", "ruff 0.9.7", ruff_json)
    _install_json_tool(install_fake_tool, "bandit", "bandit 1.9.0", bandit_json)

    report = ScanEngine().scan(repo)

    outcomes = {item.analyzer_name: item for item in report.analyzer_outcomes}
    assert outcomes["ruff-python-lint"].status == AnalyzerStatus.COMPLETED
    assert outcomes["bandit-python-security"].status == AnalyzerStatus.COMPLETED
    assert "ruff" in (outcomes["ruff-python-lint"].message or "").lower()
    for name in ("repolens-structure", "dependency-manifests", "testing-hygiene"):
        assert outcomes[name].status == AnalyzerStatus.COMPLETED

    rule_ids = [finding.rule_id for finding in report.findings]
    assert "RUFF-F401" in rule_ids
    assert "RUFF-F841" in rule_ids
    assert "BANDIT-B307" in rule_ids
    assert "RL-DOC-003" in rule_ids  # README links to a missing file
    assert "RL-TEST-001" in rule_ids  # no tests
    assert "RL-DEP-005" in rule_ids  # unpinned runtime dependency

    # Severity ordering is deterministic.
    ranks = [finding.severity.rank for finding in report.findings]
    assert ranks == sorted(ranks, reverse=True)

    # The report is serializable and AI advisories stay empty in Stage 2.
    round_tripped = ScanReport.model_validate_json(report.model_dump_json())
    assert [f.fingerprint for f in round_tripped.findings] == [
        f.fingerprint for f in report.findings
    ]
    assert report.ai_advisories == []
    assert all(finding.source.kind.value == "deterministic" for finding in report.findings)


def test_clean_repository_is_quiet(
    make_python_repo: Callable[..., Path],
    tmp_path: Path,
    install_fake_tool: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    empty_ruff = tmp_path / "ruff-empty.json"
    empty_ruff.write_text("[]", encoding="utf-8")
    empty_bandit = tmp_path / "bandit-empty.json"
    empty_bandit.write_text('{"results": []}', encoding="utf-8")
    _install_json_tool(install_fake_tool, "ruff", "ruff 0.9.7", empty_ruff)
    _install_json_tool(install_fake_tool, "bandit", "bandit 1.9.0", empty_bandit)

    report = ScanEngine().scan(repo)
    assert report.findings == []


def test_biome_findings_end_to_end(
    make_jsts_repo: Callable[..., Path],
    tmp_path: Path,
    install_fake_tool: Callable[..., Path],
) -> None:
    repo = make_jsts_repo()
    payload = {
        "summary": {"errors": 1},
        "diagnostics": [
            {
                "severity": "error",
                "message": "Unexpected debugger statement.",
                "category": "lint/suspicious/noDebugger",
                "location": {
                    "path": str(repo / "src" / "index.ts"),
                    "start": {"line": 2, "column": 1},
                    "end": {"line": 2, "column": 10},
                },
            }
        ],
    }
    biome_json = tmp_path / "biome.json.out"
    biome_json.write_text(json.dumps(payload), encoding="utf-8")
    _install_json_tool(install_fake_tool, "biome", "Version: 2.6.3", biome_json)

    report = ScanEngine().scan(repo)

    outcome = next(o for o in report.analyzer_outcomes if o.analyzer_name == "biome-jsts-lint")
    assert outcome.status == AnalyzerStatus.COMPLETED
    finding = next(f for f in report.findings if f.rule_id == "BIOME-noDebugger")
    assert finding.location is not None
    assert finding.location.path == "src/index.ts"
    assert finding.source.tool_version == "2.6.3"


def test_tool_timeout_is_reported_and_isolated(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    install_fake_tool("ruff", "time.sleep(30)\n", version="ruff 0.9.7")
    repo = tmp_path / "slow"
    repo.mkdir()
    _write(repo, "app.py", "import os\n")

    config = ScanConfig(subprocess_timeout_seconds=0.3)
    report = ScanEngine(
        config=config,
        analyzers=[
            *[a for a in default_analyzers() if a.name == "repolens-structure"],
            *[a for a in default_analyzers() if a.name == "ruff-python-lint"],
        ],
    ).scan(repo)

    outcomes = {item.analyzer_name: item for item in report.analyzer_outcomes}
    assert outcomes["ruff-python-lint"].status == AnalyzerStatus.TIMED_OUT
    assert outcomes["repolens-structure"].status == AnalyzerStatus.COMPLETED


def test_tool_crash_is_isolated_from_other_analyzers(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    repo = _python_repo(tmp_path)
    core = repo / "src" / "demo" / "core.py"
    ruff_json = tmp_path / "ruff.json"
    ruff_json.write_text(json.dumps(_ruff_payload(core)), encoding="utf-8")
    _install_json_tool(install_fake_tool, "ruff", "ruff 0.9.7", ruff_json)
    install_fake_tool(
        "bandit",
        'sys.stderr.write("internal error\\n")\nraise SystemExit(2)\n',
        version="bandit 1.9.0",
    )

    report = ScanEngine(
        analyzers=[
            *[
                a
                for a in default_analyzers()
                if a.name in {"ruff-python-lint", "bandit-python-security"}
            ]
        ]
    ).scan(repo)

    outcomes = {item.analyzer_name: item for item in report.analyzer_outcomes}
    assert outcomes["ruff-python-lint"].status == AnalyzerStatus.COMPLETED
    assert outcomes["bandit-python-security"].status == AnalyzerStatus.FAILED
    assert any(finding.rule_id == "RUFF-F401" for finding in report.findings)


def test_missing_tools_are_reported_as_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    from repolens.analyzers.tooling import clear_tool_cache

    clear_tool_cache()

    repo = tmp_path / "plain"
    repo.mkdir()
    _write(repo, "app.py", "import os\n")
    _write(repo, "src/app.ts", "export const x = 1;\n")

    report = ScanEngine().scan(repo)
    outcomes = {item.analyzer_name: item for item in report.analyzer_outcomes}
    assert outcomes["ruff-python-lint"].status == AnalyzerStatus.UNAVAILABLE
    assert outcomes["bandit-python-security"].status == AnalyzerStatus.UNAVAILABLE
    assert outcomes["biome-jsts-lint"].status == AnalyzerStatus.UNAVAILABLE
    assert "PATH" in (outcomes["ruff-python-lint"].message or "")
    # Offline analyzers still ran.
    assert outcomes["repolens-structure"].status == AnalyzerStatus.COMPLETED


def test_repeated_scans_are_deterministic(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    repo = _python_repo(tmp_path)
    core = repo / "src" / "demo" / "core.py"
    ruff_json = tmp_path / "ruff.json"
    ruff_json.write_text(json.dumps(_ruff_payload(core)), encoding="utf-8")
    _install_json_tool(install_fake_tool, "ruff", "ruff 0.9.7", ruff_json)

    analyzer = [a for a in default_analyzers() if a.name == "ruff-python-lint"]
    first = ScanEngine(analyzers=analyzer).scan(repo)
    second = ScanEngine(analyzers=analyzer).scan(repo)

    assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]
    assert [f.rule_id for f in first.findings] == [f.rule_id for f in second.findings]


def test_duplicate_tool_diagnostics_are_deduplicated(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    repo = _python_repo(tmp_path)
    core = repo / "src" / "demo" / "core.py"
    duplicated = _ruff_payload(core) * 2
    ruff_json = tmp_path / "ruff.json"
    ruff_json.write_text(json.dumps(duplicated), encoding="utf-8")
    _install_json_tool(install_fake_tool, "ruff", "ruff 0.9.7", ruff_json)

    report = ScanEngine(
        analyzers=[a for a in default_analyzers() if a.name == "ruff-python-lint"]
    ).scan(repo)

    assert len(report.findings) == 2
    assert len({finding.fingerprint for finding in report.findings}) == 2


def test_osv_and_external_tools_coexist(
    tmp_path: Path, install_fake_tool: Callable[..., Path]
) -> None:
    from repolens.osv import OsvPackage, OsvVulnerability

    repo = tmp_path / "osv"
    repo.mkdir()
    _write(repo, "requirements.txt", "requests==2.31.0\n")
    _write(repo, "app.py", "import os\n")

    class Client:
        def query(self, packages: Sequence[OsvPackage]) -> list[OsvVulnerability]:
            return [
                OsvVulnerability(
                    vuln_id="GHSA-1111-2222-3333",
                    package=packages[0],
                    summary="Advisory summary",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                )
            ]

    ruff_json = tmp_path / "ruff.json"
    ruff_json.write_text(json.dumps(_ruff_payload(repo / "app.py")), encoding="utf-8")
    _install_json_tool(install_fake_tool, "ruff", "ruff 0.9.7", ruff_json)

    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[
            OsvVulnerabilityAnalyzer(client_factory=lambda cfg: Client()),
            *[a for a in default_analyzers() if a.name == "ruff-python-lint"],
        ],
    ).scan(repo)

    outcomes = {item.analyzer_name: item for item in report.analyzer_outcomes}
    assert outcomes["osv-dependency-check"].status == AnalyzerStatus.COMPLETED
    assert outcomes["ruff-python-lint"].status == AnalyzerStatus.COMPLETED
    assert {finding.rule_id for finding in report.findings} == {
        "OSV-GHSA-1111-2222-3333",
        "RUFF-F401",
        "RUFF-F841",
    }


def test_scan_does_not_modify_repository(
    make_jsts_repo: Callable[..., Path],
    tmp_path: Path,
    install_fake_tool: Callable[..., Path],
) -> None:
    repo = make_jsts_repo()
    before = {
        path.relative_to(repo).as_posix(): path.stat().st_mtime_ns
        for path in repo.rglob("*")
        if path.is_file()
    }
    biome_json = tmp_path / "biome.out"
    biome_json.write_text('{"diagnostics": []}', encoding="utf-8")
    _install_json_tool(install_fake_tool, "biome", "Version: 2.6.3", biome_json)

    ScanEngine().scan(repo)

    after = {
        path.relative_to(repo).as_posix(): path.stat().st_mtime_ns
        for path in repo.rglob("*")
        if path.is_file()
    }
    assert after == before
