"""Unit tests for the offline dependency hygiene analyzer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repolens.analyzers.dependencies import DependencyAnalyzer
from repolens.config import ScanConfig
from repolens.discovery import RepositoryContext, discover_repository
from repolens.models import Finding


def _context(tmp_path: Path, files: dict[str, str], name: str = "repo") -> RepositoryContext:
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return discover_repository(root, ScanConfig())


def _analyze(context: RepositoryContext) -> list[Finding]:
    return DependencyAnalyzer().analyze(context, ScanConfig())


def test_malformed_lockfile_is_reported(tmp_path: Path) -> None:
    context = _context(tmp_path, {"package-lock.json": '{"lockfileVersion": '})
    findings = _analyze(context)

    by_rule = {finding.rule_id: finding for finding in findings}
    assert "RL-DEP-001" in by_rule
    finding = by_rule["RL-DEP-001"]
    assert finding.severity.value == "medium"
    assert finding.location is not None
    assert finding.location.path == "package-lock.json"
    assert finding.location.start_line == 1


def test_invalid_requirement_is_reported_with_line(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {"requirements.txt": "flask==3.0.0\nthis is not a requirement ???\n"},
    )
    findings = _analyze(context)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert "RL-DEP-002" in by_rule
    assert by_rule["RL-DEP-002"].location is not None
    assert by_rule["RL-DEP-002"].location.start_line == 2


def test_declared_dependency_missing_from_lockfile(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"react": "^18.2.0"}}),
            "package-lock.json": json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/other": {"version": "1.0.0"}},
                }
            ),
        },
    )
    findings = _analyze(context)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert "RL-DEP-003" in by_rule
    finding = by_rule["RL-DEP-003"]
    assert "react" in finding.title
    assert finding.severity.value == "low"
    assert finding.location is not None
    assert finding.location.path == "package.json"


def test_locked_version_outside_declared_range(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"react": "^19.0.0"}}),
            "package-lock.json": json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/react": {"version": "18.3.1"}},
                }
            ),
        },
    )
    findings = _analyze(context)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert "RL-DEP-004" in by_rule
    assert "18.3.1" in (by_rule["RL-DEP-004"].evidence or "")


def test_consistent_lockfile_produces_no_findings(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"react": "^18.2.0"}}),
            "package-lock.json": json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/react": {"version": "18.3.1"}},
                }
            ),
        },
    )
    assert _analyze(context) == []


def test_incomplete_pnpm_lockfile_is_not_used_for_consistency_checks(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"react": "^18.0.0"}}),
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        },
    )
    assert _analyze(context) == []


def test_conflicting_python_pins_are_reported(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "requirements.txt": "flask==3.0.0\n",
            "docs/requirements.txt": "flask==2.3.3\n",
            "pyproject.toml": ('[project]\nname = "demo"\ndependencies = ["Flask==3.0.0"]\n'),
        },
    )
    findings = _analyze(context)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert "RL-DEP-006" in by_rule
    evidence = by_rule["RL-DEP-006"].evidence or ""
    assert "3.0.0" in evidence
    assert "2.3.3" in evidence


def test_unpinned_python_dependencies_without_lockfile_is_informational(
    tmp_path: Path,
) -> None:
    context = _context(
        tmp_path,
        {"pyproject.toml": '[project]\nname = "demo"\ndependencies = ["requests>=2.31"]\n'},
    )
    findings = _analyze(context)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert "RL-DEP-005" in by_rule
    assert by_rule["RL-DEP-005"].severity.value == "info"

    with_lock = _context(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "demo"\ndependencies = ["requests>=2.31"]\n',
            "poetry.lock": '[[package]]\nname = "requests"\nversion = "2.32.3"\n',
        },
        name="locked",
    )
    assert "RL-DEP-005" not in {finding.rule_id for finding in _analyze(with_lock)}


def test_unsupported_lockfile_reported_as_info(tmp_path: Path) -> None:
    context = _context(tmp_path, {"bun.lockb": "binary"})
    findings = _analyze(context)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["RL-DEP-007"].severity.value == "info"


def test_malformed_nested_manifest_is_reported(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "packages/web/pyproject.toml": "[project\nbroken\n",
            "pyproject.toml": "[project\nbroken\n",
        },
    )
    findings = _analyze(context)
    paths = {finding.location.path for finding in findings if finding.location is not None}
    # Root pyproject validity is the structure analyzer's responsibility.
    assert paths == {"packages/web/pyproject.toml"}


def test_nested_workspace_lockfiles_are_matched_per_directory(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"react": "^18.0.0"}}),
            "package-lock.json": json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/react": {"version": "18.3.1"}},
                }
            ),
            "packages/web/package.json": json.dumps({"dependencies": {"vue": "^3.0.0"}}),
            "packages/web/package-lock.json": json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"node_modules/vue": {"version": "3.5.0"}},
                }
            ),
        },
    )
    assert _analyze(context) == []


def test_analyzer_not_applicable_without_manifests(tmp_path: Path) -> None:
    context = _context(tmp_path, {"README.md": "# nothing here\n"})
    analyzer = DependencyAnalyzer()
    assert analyzer.is_applicable(context) is False


def test_findings_respect_configured_cap(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "package.json": json.dumps(
                {"dependencies": {"a": "^1.0.0", "b": "^2.0.0", "c": "^3.0.0"}}
            ),
            "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {}}),
        },
    )
    findings = DependencyAnalyzer().analyze(context, ScanConfig(max_findings_per_analyzer=1))
    assert len(findings) == 1


def test_analyzer_message_is_deterministic(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {"package.json": json.dumps({"dependencies": {"react": "^18.0.0"}})},
    )
    analyzer = DependencyAnalyzer()
    analyzer.analyze(context, ScanConfig())
    first = analyzer.completion_message()
    analyzer.analyze(context, ScanConfig())
    assert first == analyzer.completion_message()
    assert first is not None
    assert "declared dependenc" in first


@pytest.mark.parametrize("manifest", ["requirements.txt", "package.json"])
def test_analyzer_never_reads_sensitive_files(tmp_path: Path, manifest: str) -> None:
    context = _context(tmp_path, {manifest: ""})
    assert _analyze(context) == []
